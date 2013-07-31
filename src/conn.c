#include <libfutil/conn.h>

/* XXX: conn_id + connset_id are not mutex'ed thus could race in theory */

/*
 * For the keyfile.pem + server.pem use:
 *
 *	openssl req -newkey rsa:1024 -x509 -nodes -keyout keyfile.pem \
 *	 	    -new -out server.pem
 */

/* Forward, only used internally as they are the non-mutexed version */
static void conn_eventsA(conn_t *conn, uint16_t events);
static void conn_set_connset(conn_t *conn, connset_t *cs);
static int conn_recvA(conn_t *conn);

#ifdef _WIN32
/* Windows writev() support */
struct iovec {
	u_long	iov_len;
        char	*iov_base;
};

/* Windows doesn't have writev() but does have WSASend */
static int
writev(socket_t sock, const struct iovec *vector, DWORD count) {
	DWORD sent;

	WSASend(sock, (LPWSABUF)vector, count, &sent, 0, NULL, NULL);

	return (sent);
}
#endif

void
connset_lock(connset_t *cs);
void
connset_lock(connset_t *cs) {
	mutex_lock(cs->mutex);
}

void
connset_unlock(connset_t *cs);
void
connset_unlock(connset_t *cs) {
	mutex_unlock(cs->mutex);
}

void
conn_lock(conn_t *conn);
void
conn_lock(conn_t *conn) {
	mutex_lock(conn->mutex);
}

void
conn_unlock(conn_t *conn);
void
conn_unlock(conn_t *conn) {
	mutex_unlock(conn->mutex);
}

static void
conn_set_nonblocking(conn_t *conn) {
#ifndef _WIN32
	int flags;
#else
	u_long flags;
#endif

	assert(conn_is_valid(conn));

#if defined(O_NONBLOCK) && defined(F_SETFL) && defined(F_GETFL)
	if (-1 == (flags = fcntl(conn->sock, F_GETFL, 0))) flags = 0;
	fcntl(conn->sock, F_SETFL, flags | O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 1;
	ioctlsocket(conn->sock, FIOBIO, &flags);
#endif
}

static void
conn_set_blocking(conn_t *conn) {
#ifndef _WIN32
	int flags;
#else
	u_long flags;
#endif

#ifdef O_NONBLOCK
	if (-1 == (flags = fcntl(conn->sock, F_GETFL, 0))) flags = 0;
	fcntl(conn->sock, F_SETFL, flags & ~O_NONBLOCK);
#else
	/* Otherwise, use the old way of doing it */
	flags = 0;
	ioctlsocket(conn->sock, FIOBIO, &flags);
#endif
}

bool
conn_is_state(conn_t *conn, connstate_t st) {
	assert(conn);

	if (conn->state == st)
		return (true);

	return (false);
}

#ifdef CONN_SSL
static void conn_ssl_bio(conn_t *conn);

static void
conn_ssl_err(conn_t *conn, const char *format, ...) ATTR_FORMAT(printf, 2, 3);
static void
conn_ssl_err(conn_t *conn, const char *format, ...) {
	va_list	ap;
	char	err[256], msg[256];
	int	se = conn && conn->ssl ? SSL_get_error(conn->ssl, -1) : 0;

        va_start(ap, format);

	ERR_error_string_n(ERR_get_error(), err, sizeof err);
	vsnprintf(msg, sizeof msg, format, ap);

	logline(log_WARNING_, CONN_ID " SSL Error: %s :: %s (%u / %s)",
		conn_id(conn), msg, err, se,
		se == SSL_ERROR_WANT_READ ?	"Want Read" :
		se == SSL_ERROR_WANT_WRITE ?	"Want Write" :
						"Other");

        va_end(ap);
}

static unsigned int
conn_ssl_psk_server_cb(SSL *ssl, const char *identity,
		unsigned char *psk, unsigned int max_psk_len)
{
	conn_t		*conn = (conn_t *)SSL_get_app_data(ssl);
	unsigned int	psk_len = 0;
	int		ret;
	BIGNUM		*bn = NULL;

	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

	/* Required to be there */
	assert(conn->ssl_psk_id != NULL);
	assert(conn->ssl_psk_key != NULL);

	if (!identity) {
		logline(log_NOTICE_, CONN_ID " client did not send PSK identity",
			conn_id(conn));
		return (0);
	}

	logline(log_DEBUG_,
		CONN_ID " identity_len: %u, identity: %s",
		conn_id(conn),
		(unsigned int)strlen(identity), identity);

	/* Is it the identity we expect? */
	if (strcmp(identity, conn->ssl_psk_id) != 0)
	{
		logline(log_NOTICE_,
		 	CONN_ID " PSK error: client identity not found"
			" (got '%s' expected '%s')n",
			conn_id(conn), identity, conn->ssl_psk_id);
		return (0);
	}

	logline(log_DEBUG_, CONN_ID " PSK client identity found", conn_id(conn));

	/* convert the PSK key to binary */
	ret = BN_hex2bn(&bn, conn->ssl_psk_key);
	if (!ret)
	{
		logline(log_NOTICE_,
			CONN_ID " Could not convert PSK key '%s' to BIGNUM",
			conn_id(conn), conn->ssl_psk_key);
		if (bn) {
			BN_free(bn);
		}
		return (0);
	}

	if (BN_num_bytes(bn) > (int)max_psk_len)
	{
		logline(log_NOTICE_,
			CONN_ID " psk buffer of callback is too small (%u) "
			"for key (%u)",
			conn_id(conn), max_psk_len, BN_num_bytes(bn));
		BN_free(bn);
		return (0);
	}

	ret = BN_bn2bin(bn, psk);
	BN_free(bn);

	if (ret < 0) {
		logline(log_NOTICE_,
			CONN_ID " bn2bin failed for PSK",
			conn_id(conn));
		return(0);
	}

	psk_len = (unsigned int)ret;

	logline(log_DEBUG_,
		CONN_ID " Fetched PSK len=%u\n",
		conn_id(conn), psk_len);
	return (psk_len);
}

static unsigned int
conn_ssl_psk_client_cb(SSL *ssl, const char *hint, char *identity,
	      unsigned int max_identity_len, unsigned char *psk,
              unsigned int max_psk_len)
{
	conn_t		*conn = (conn_t *)SSL_get_app_data(ssl);
	unsigned int	psk_len = 0;
	int		n;
	BIGNUM		*bn = NULL;

	logline(log_DEBUG_, CONN_ID "", conn_id(conn));
	if (!hint) {
		logline(log_DEBUG_,
			CONN_ID " NULL PSK identity hint", conn_id(conn));
	} else {
		logline(log_DEBUG_, CONN_ID " PSK identity hint \"%s\"",
			conn_id(conn), hint);
	}

	/*
	 * lookup PSK identity and PSK key based on the given
	 * identity hint here
	 */
	n = snprintf(identity, max_identity_len, "%s", conn->ssl_psk_id);
	if (!snprintfok(n, max_identity_len)) {
		logline(log_ERR_, CONN_ID " Could not store identity", conn_id(conn));
		return (0);
	}

	logline(log_DEBUG_, CONN_ID " identity: \"%s\" (%u)",conn_id(conn),identity,n);

	n = BN_hex2bn(&bn, conn->ssl_psk_key);
	if (!n)
	{
		logline(log_ERR_,
			CONN_ID " Could not convert PSK key '%s' to BIGNUM",
			conn_id(conn), conn->ssl_psk_key);
		if (bn)
			BN_free(bn);
		return (0);
	}

	if ((unsigned int)BN_num_bytes(bn) > max_psk_len)
	{
		logline(log_ERR_, CONN_ID " psk buffer of callback is too "
			" small (%d) for key (%d)",
			conn_id(conn), max_psk_len, BN_num_bytes(bn));
		BN_free(bn);
		return (0);
	}

	psk_len = BN_bn2bin(bn, psk);
	BN_free(bn);

	if (psk_len == 0) {
		logline(log_ERR_, CONN_ID " psk_len = %u", conn_id(conn), psk_len);
		return (0);
	}

	logline(log_DEBUG_, CONN_ID " Created PSK len = %u", conn_id(conn), psk_len);
	return (psk_len);
}

static void
conn_ssl_info_cb(const SSL *ssl, int where, int ret) {
	conn_t		*conn = (conn_t *)SSL_get_app_data(ssl);
	const char	*str;
	int		w;

	w = where & ~SSL_ST_MASK;

	if (w & SSL_ST_CONNECT) {
		str = "SSL_connect";
	} else if (w & SSL_ST_ACCEPT) {
		str = "SSL_accept";
	} else {
		str = "undefined";
	}

	if (where & SSL_CB_LOOP) {
		logline(log_DEBUG_,
			CONN_ID " %s:%s (%d)",
			conn_id(conn), str, SSL_state_string_long(ssl), ret);
	} else if (where & SSL_CB_ALERT) {
		logline(log_DEBUG_,
			CONN_ID " SSL3 alert %s:%s:%s (%d)",
			conn_id(conn),
			(where & SSL_CB_READ) ? "read" : "write",
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret), ret);
	}
	else if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			logline(log_DEBUG_,
				CONN_ID " %s:failed in %s (%d)",
				conn_id(conn), str,
				SSL_state_string_long(ssl), ret);
		} else if (ret < 0) {
			logline(log_DEBUG_,
				CONN_ID " %s:error in %s (%d)",
				conn_id(conn), str,
				SSL_state_string_long(ssl), ret);
		}
	} else {
		logline(log_DEBUG_,
			CONN_ID " Callback %s:%s:%s (%d)",
			conn_id(conn),
			(where & SSL_CB_READ) ? "read" : "write",
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret), ret);
	}
}

static void
conn_ssl_msg_cb(int write_p, int version, int content_type,
		const void *buf, size_t len, SSL *ssl,
		void UNUSED *arg)
{
	conn_t		*conn = (conn_t *)SSL_get_app_data(ssl);
        const char	*str_write_p, *str_version, *str_content_type = "",
			*str_details1 = "", *str_details2= "";

        str_write_p = write_p ? ">>>" : "<<<";

	switch (version) {
	case SSL2_VERSION:
		str_version = "SSL 2.0";
		break;
	case SSL3_VERSION:
		str_version = "SSL 3.0 ";
		break;
	case TLS1_VERSION:
		str_version = "TLS 1.0 ";
		break;
	case DTLS1_VERSION:
		str_version = "DTLS 1.0 ";
		break;
	case DTLS1_BAD_VER:
		str_version = "DTLS 1.0 (bad) ";
		break;
	default:
		str_version = "???";
	}

	if (version == SSL2_VERSION) {
		unsigned int err;
		str_details1 = "???";

		if (len > 0) {
			switch (((const unsigned char*)buf)[0]) {
			case 0:
				str_details1 = ", ERROR:";
				str_details2 = " ???";

				if (len < 3)
					break;

				err = (((const unsigned char*)buf)[1]<<8)  +
				       ((const unsigned char*)buf)[2];

				switch (err) {
				case 0x0001:
					str_details2 = " NO-CIPHER-ERROR";
					break;
				case 0x0002:
					str_details2 = " NO-CERT-ERROR";
					break;
				case 0x0004:
					str_details2 = " BAD-CERT-ERROR";
					break;
				case 0x0006:
					str_details2 = " UNSUPPORTED-CERT-"
						       "TYPE-ERROR";
					break;
				default:
					break;
				}

				break;
			case 1:
				str_details1 = ", CLIENT-HELLO";
				break;
			case 2:
				str_details1 = ", CLIENT-MASTER-KEY";
				break;
			case 3:
				str_details1 = ", CLIENT-FINISHED";
				break;
			case 4:
				str_details1 = ", SERVER-HELLO";
				break;
			case 5:
				str_details1 = ", SERVER-VERIFY";
				break;
			case 6:
				str_details1 = ", SERVER-FINISHED";
				break;
			case 7:
				str_details1 = ", REQUEST-CERTIFICATE";
				break;
			case 8:
				str_details1 = ", CLIENT-CERTIFICATE";
				break;
			default:
				break;
			}
		}
	}

	if (	version == SSL3_VERSION ||
		version == TLS1_VERSION ||
		version == DTLS1_VERSION ||
		version == DTLS1_BAD_VER) {

		switch (content_type) {
		case 20:
			str_content_type = "ChangeCipherSpec";
			break;
		case 21:
			str_content_type = "Alert";
			break;
		case 22:
			str_content_type = "Handshake";
			break;
		default:
			break;
		}

		if (content_type == 21) { /* Alert */
			str_details1 = ", ???";

			if (len == 2) {
				switch (((const unsigned char*)buf)[0])
				{
				case 1:
					str_details1 = ", warning";
					break;
				case 2:
					str_details1 = ", fatal";
					break;
				default:
					break;
				}

				str_details2 = " ???";
				switch (((const unsigned char*)buf)[1])
				{
				case 0:
					str_details2 = " close_notify";
					break;
				case 10:
					str_details2 = " unexpected_message";
					break;
				case 20:
					str_details2 = " bad_record_mac";
					break;
				case 21:
					str_details2 = " decryption_failed";
					break;
				case 22:
					str_details2 = " record_overflow";
					break;
				case 30:
					str_details2 = " decompression_fail";
					break;
				case 40:
					str_details2 = " handshake_failure";
					break;
				case 42:
					str_details2 = " bad_certificate";
					break;
				case 43:
					str_details2 = " unsupported_cert";
					break;
				case 44:
					str_details2 = " certificate_revoked";
					break;
				case 45:
					str_details2 = " certificate_expired";
					break;
				case 46:
					str_details2 = " certificate_unknown";
					break;
				case 47:
					str_details2 = " illegal_parameter";
					break;
				case 48:
					str_details2 = " unknown_ca";
					break;
				case 49:
					str_details2 = " access_denied";
					break;
				case 50:
					str_details2 = " decode_error";
					break;
				case 51:
					str_details2 = " decrypt_error";
					break;
				case 60:
					str_details2 = " export_restriction";
					break;
				case 70:
					str_details2 = " protocol_version";
					break;
				case 71:
					str_details2 = " insufficient_sec";
					break;
				case 80:
					str_details2 = " internal_error";
					break;
				case 90:
					str_details2 = " user_canceled";
					break;
				case 100:
					str_details2 = " no_renegotiation";
					break;
				case 110:
					str_details2 = " unsupported_ext";
					break;
				case 111:
					str_details2 = " certificate_404";
					break;
				case 112:
					str_details2 = " unrecognized_name";
					break;
				case 113:
					str_details2 = " bad_certificate_"
							"status_response";
					break;
				case 114:
					str_details2 = " bad_certificate_"
							"hash_value";
					break;
				default:
					break;
				}
			}
		}
		
		if (content_type == 22) { /* Handshake */
			str_details1 = "???";

			if (len > 0) {
				switch (((const unsigned char*)buf)[0]) {
				case 0:
					str_details1 = ", HelloRequest";
					break;
				case 1:
					str_details1 = ", ClientHello";
					break;
				case 2:
					str_details1 = ", ServerHello";
					break;
				case 3:
					str_details1 = ", HelloVerifyRequest";
					break;
				case 11:
					str_details1 = ", Certificate";
					break;
				case 12:
					str_details1 = ", ServerKeyExchange";
					break;
				case 13:
					str_details1 = ", CertificateRequest";
					break;
				case 14:
					str_details1 = ", ServerHelloDone";
					break;
				case 15:
					str_details1 = ", CertificateVerify";
					break;
				case 16:
					str_details1 = ", ClientKeyExchange";
					break;
				case 20:
					str_details1 = ", Finished";
					break;
				default:
					break;
				}
			}
		}
	}

	logline(log_DEBUG_, CONN_ID " %s %s%s [length %04lx]%s%s\n",
		conn_id(conn), str_write_p, str_version, str_content_type,
		(unsigned long)len, str_details1, str_details2);

	if (len > 0) {
		size_t num, i;

		fprintf(stderr, "   ");
		num = len;

		for (i = 0; i < num; i++) {
			if (i % 16 == 0 && i > 0)
				fprintf(stderr, "\n   ");
			fprintf(stderr, " %02x",
				((const unsigned char*)buf)[i]);
		}

		if (i < len)
			fprintf(stderr, " ...");

		fprintf(stderr, "\n");
	}
}

void
conn_ssl_cleanup(SSL_CTX *ssl_ctx) {
	logline(log_DEBUG_, "...");

	if (ssl_ctx) {
		SSL_CTX_free(ssl_ctx);
	}

	OBJ_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ENGINE_cleanup();

	ERR_remove_state(0);
	ERR_remove_thread_state(NULL);

	ERR_free_strings();

	CRYPTO_mem_leaks_fp(stderr);
}

SSL_CTX *
conn_ssl_init(bool serverside) {
	static bool		initialized = false;
	SSL_CTX			*ctx;
	const SSL_METHOD	*m;

	logline(log_DEBUG_, "...");

	if (!initialized) {
		logline(log_DEBUG_, "Initializing SSL");
		SSL_library_init();
		SSL_load_error_strings();
		OpenSSL_add_ssl_algorithms();
		ENGINE_register_all_complete();
		initialized = true;
	}

	/* Create our context */
	m = SSLv23_method();
	if (!m) {
		conn_ssl_err(NULL, "SSL method failed");
		return (NULL);
	}

	ctx = SSL_CTX_new(m);
	if (!ctx) {
		conn_ssl_err(NULL, "SSL context failed");
		return (NULL);
	}

	SSL_CTX_set_options(ctx, 0);
	SSL_CTX_set_session_id_context(ctx, (const unsigned char *)"sid", 4);

	/* Provide a lot of debugging output */
	SSL_CTX_set_info_callback(ctx, conn_ssl_info_cb);
	SSL_CTX_set_msg_callback(ctx, conn_ssl_msg_cb);

	/* We use PSK */
	if (serverside) {
		SSL_CTX_set_psk_server_callback(ctx, conn_ssl_psk_server_cb);

		/* Pick a Cipher that can do PSK */
		if (SSL_CTX_set_cipher_list(ctx, "PSK-AES256-CBC-SHA") != 1)
		{
			conn_ssl_err(NULL, "Could not set PSK cipher\n");
			conn_ssl_cleanup(ctx);
			return (NULL);
		}
	} else {
		SSL_CTX_set_psk_client_callback(ctx, conn_ssl_psk_client_cb);

		/* Pick a Cipher that can do PSK */
		if (SSL_CTX_set_cipher_list(ctx, "PSK") != 1)
		{
			conn_ssl_err(NULL, "Could not set PSK cipher\n");
			conn_ssl_cleanup(ctx);
			return (NULL);
		}
	}

	/* Don't verify anything */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	return (ctx);
}
#endif /* CONN_SSL */

void
conn_set_state(conn_t *conn, connstate_t state) {
	const char	*states[] = {
				"UNUSED", "LISTENING", "ACCEPTING",
				"CONNECTING", "CONNECTED" },
			*st;

	st = state < lengthof(states) ? states[state] : "?UNKNOWN!";

	logline(log_DEBUG_, CONN_ID " is now %s", conn_id(conn), st);

	conn->state = state;
}

bool
conn_init(conn_t *conn, void *clientdata)
{
	/* Unique connection number, for easy debugging */
	static uint64_t conn_id = 0;

#ifdef _WIN32

	if (conn_id == 0) {
		/* Initialize Winsock */
		WSADATA WsaDat;

		if (WSAStartup(MAKEWORD(2,2), &WsaDat) != 0) {
			logline(log_CRIT_,
				"Winsock error - Initialization failed");
			WSACleanup();
			return (false);
		}
	}
#else
        /* Ignore SIGPIPE for when we read/write and the connection breaks */
        signal(SIGPIPE, SIG_IGN);
#endif

	assert(conn != NULL);

	/* Empty it out */
	memzero(conn, sizeof *conn);

	/* Give it a number we can remember */
	conn->id = ++conn_id;
	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

	node_init(&conn->node);
	mutex_init(conn->mutex);

	/* Init the buffers */
	if (	!buf_init(&conn->recv) ||
		!buf_init(&conn->send) ||
		!buf_init(&conn->send_headers)) {
		return (false);
	}

	/* 2 MiB incoming */
	buf_minsize(&conn->recv, 2 * 1024 * 1024);

	/* Initial assignment */
	conn->sock = INVALID_SOCKET;
	conn->connset = NULL;
	conn->clientdata = clientdata;
	conn_set_state(conn, CONN_UNUSED);
	conn->add_contentlen = true;

	return (true);
}

/* Locked by caller */
void
conn_set_connset(conn_t *conn, connset_t *cs) {
	uint16_t events = conn->wntevents;
	bool	first = false;

	/* 
	 * With a connset it is a non-blocking socket
	 * Without a connset it is a blocking socket
	 */

	/* Nothing to do if it is the same connset */
	if (conn->connset == cs)
		return;

	/* Remove from old connset */
	if (conn->connset != NULL)
		conn_eventsA(conn, 0);
	else
		first = true;

	/* Add to new connset */
	if (cs != NULL) {
		if (first) {
			/* First time add, thus put it on a list */
			logline(log_DEBUG_, "first time");
			list_addtail_l(&cs->inactive, &conn->node);
		}

		conn_eventsA(conn, events);
	}

	conn->connset = cs;
}

/* Destroy the connection, final cleanup */
void
conn_destroy(conn_t *conn) {
	logline(log_DEBUG_, "(%p) " CONN_ID, (void *)conn, conn_id(conn));

	/* Close the socket first if needed */
	conn_close(conn);

	logline(log_DEBUG_, CONN_ID " destroying buffers", conn_id(conn));

	buf_destroy(&conn->recv);
	buf_destroy(&conn->send);
	buf_destroy(&conn->send_headers);

	/* Unlink the node from any list it was put on */
	if (conn->connset != NULL) {
		/* conn_close() made this inactive */
		list_remove_l(&conn->connset->inactive, &conn->node);

		/* No more conset here */
		conn->connset = NULL;
	}

	mutex_destroy(conn->mutex);
	node_destroy(&conn->node);

	logline(log_DEBUG_, CONN_ID " gone", conn_id(conn));

	/* Clean her out */
	memzero(conn, sizeof *conn);
}

void
connset_init(connset_t *cs) {
	/* Unique connection number, for easy debugging */
	static unsigned int	connset_id = 0;

	/* A new one */
	memzero(cs, sizeof *cs);
	cs->id = ++connset_id;

	mutex_init(cs->mutex);
	list_init(&cs->active);
	list_init(&cs->ready);
	list_init(&cs->inactive);

	logline(log_DEBUG_,
		"active: " LIST_ID
		", ready: " LIST_ID
		", inactive: " LIST_ID,
		list_id(&cs->active),
		list_id(&cs->ready),
		list_id(&cs->inactive)
		);

	FD_ZERO(&cs->fd_read);
	FD_ZERO(&cs->fd_write);

	/* Negative is the maximum */
	cs->hifd = -1;
}

void
connset_destroy(connset_t *cs) {
	unsigned int	i = 0;
	conn_t		*conn;

	do {
		i = 0;

		while ((conn = (conn_t *)list_pop(&cs->ready))) {
			conn->connset = NULL;
			conn->connset_l = NULL;

			i++;
			logline(log_DEBUG_,
				"closing ready " CONN_ID, conn_id(conn));
			conn_destroy(conn);
			mfree(conn, sizeof *conn, "conn");
		}

		while ((conn = (conn_t *)list_pop(&cs->active))) {
			conn->connset = NULL;
			conn->connset_l = NULL;

			i++;
			logline(log_DEBUG_,
				"closing active " CONN_ID, conn_id(conn));
			conn_destroy(conn);
			mfree(conn, sizeof *conn, "conn");
		}

		while ((conn = (conn_t *)list_pop(&cs->inactive))) {
			conn->connset = NULL;
			conn->connset_l = NULL;

			i++;
			logline(log_DEBUG_,
				"closing inactive " CONN_ID, conn_id(conn));
			conn_destroy(conn);
			mfree(conn, sizeof *conn, "conn");
		}
	} while (i > 0);

	/* Should always be empty */
	assert(connset_is_empty(cs));

	list_destroy(&cs->ready);
	list_destroy(&cs->active);
	list_destroy(&cs->inactive);
	mutex_destroy(cs->mutex);
}

int
connset_poll(connset_t *cs) {
	struct timeval	timeout;
	conn_t		*conn, *conn_next;
	fd_set		fd_r, fd_w;
	int		i, errsv;

	while (true) {
		/* logline(log_DEBUG_, "..."); */

		/* What we want to check */
		memcpy(&fd_r, &cs->fd_read, sizeof fd_r);
		memcpy(&fd_w, &cs->fd_write, sizeof fd_w);

		/* Timeout every 2 seconds to let the main program check */
		/* if it needs to abort etc */
		timeout.tv_sec = 2;
		timeout.tv_usec = 0;

		thread_setstate(thread_state_io_wait);
		errno = 0;
		i = select(cs->hifd + 1, &fd_r, &fd_w, NULL, &timeout);
 		errsv = errno;
		thread_setstate(thread_state_running);

		/* logline(log_DEBUG_, "i = %d, errno = %d", i, errsv); */

		if (i < 0) {
			/* Ignore signals */
			if (errsv == EINTR) {
				logline(log_NOTICE_, "Select Interrupted");
			} else if (errsv == EBADF) {
				/*
				 * As we are multi-threaded a
				 * socket might disappear while we are
				 * checking it
				 */
				logline(log_NOTICE_, "Bad Filedescriptor");
				continue;
			} else {
				char buf[128];

				memzero(buf, sizeof buf);
				strerror_r(errsv, buf, sizeof buf);
				logline(log_ERR_, "Select Failed: %d : %s",
					errsv, buf);
				assert(false);
			}

			return (-1);
		}

		/* Timeout */
		if (i == 0) {
			/* logline(log_DEBUG_, "Timeout"); */
			break;
		}

		/* Check clients and move them from active to ready */
		list_lock(&cs->active);
		list_for(&cs->active, conn, conn_next, conn_t *) {
			conn_lock(conn);

			logline(log_DEBUG_, CONN_ID " checking (i:%s o:%s)",
				conn_id(conn),
				yesno(conn_wnt_in(conn)),
				yesno(conn_wnt_out(conn)));

			/* No events found for this one yet */
			conn->hasevents = 0;

			connset_lock(conn->connset);
			if (FD_ISSET(conn->sock, &fd_r) && conn_wnt_in(conn)) {
				conn->hasevents |= CONN_POLLIN;
				logline(log_DEBUG_, CONN_ID " has IN", conn_id(conn));
			}

			if (FD_ISSET(conn->sock, &fd_w) && conn_wnt_out(conn)){
				conn->hasevents |= CONN_POLLOUT;
				logline(log_DEBUG_, CONN_ID " has OUT", conn_id(conn));
			}
			connset_unlock(conn->connset);

			if (conn->hasevents != 0) {
				logline(log_DEBUG_,
					CONN_ID " Adding to ready list",
					conn_id(conn));

				/*
				 * Move it to the ready list
				 * (active is locked)
				 *
				 * Clear the bits so that select() does
				 * not notice them
				 */
				connset_lock(conn->connset);
				FD_CLR(conn->sock, &conn->connset->fd_read);
				FD_CLR(conn->sock, &conn->connset->fd_write);
				connset_unlock(conn->connset);

				list_remove(&conn->connset->active,
					    &conn->node);
				list_addtail_l(&conn->connset->ready,
					       &conn->node);
				conn->connset_l = &conn->connset->ready;

				logline(log_DEBUG_,
					CONN_ID " Added to ready list",
					conn_id(conn));
			}

			conn_unlock(conn);
		}
		list_unlock(&cs->active);
	}

	return (0);
}

/* For conn_get_ready() and conn_get_one_ready() */
void
connset_set_inactive(connset_t *cs, conn_t *conn);
void
connset_set_inactive(connset_t *cs, conn_t *conn) {
	/* Lock her up */
	connset_lock(cs);

	/*
	 * we took conn from the ready list
	 * add it to inactive
	 */
	list_remove_l(&cs->inactive, &conn->node);
	conn->connset_l = &cs->inactive;

	/* Release her */
	connset_unlock(cs);
}

conn_t *
connset_get_ready(connset_t *cs) {
	conn_t *conn;

	thread_setstate(thread_state_io_next);
	conn = (conn_t *)list_getnext(&cs->ready);
	thread_setstate(thread_state_running);
	if (conn != NULL) {
		connset_set_inactive(cs, conn);
	}

	return (conn);
}

conn_t *
connset_get_one_ready(connset_t *cs) {
	conn_t *conn;

	conn = (conn_t *)list_pop(&cs->ready);
	if (conn != NULL) {
		connset_set_inactive(cs, conn);
	}

	return (conn);
}

void
connset_handled_ready(conn_t *conn) {

	/* Lock it */
	conn_lock(conn);

	logline(log_DEBUG_, "...");

	/* Should come from get_ready/get_one_ready() */
	assert(conn->connset_l != NULL);

	/* Set the bits correctly so that select() answers again */
	connset_lock(conn->connset);

	if (conn->wntevents & CONN_POLLIN) {
		FD_SET(conn->sock, &conn->connset->fd_read);
	}

	if (conn->wntevents & CONN_POLLOUT) {
		FD_SET(conn->sock, &conn->connset->fd_write);
	}

	connset_unlock(conn->connset);

	/* Place it back on the active/inactive list */
	if (conn->wntevents == CONN_POLLNONE) {
		/* Already inactive */
	} else {
		list_remove_l(conn->connset_l, &conn->node);
		list_addtail_l(&conn->connset->active, &conn->node);
		conn->connset_l = &conn->connset->active;
	}

	logline(log_DEBUG_, "(done)");

	/* Release it */
	conn_unlock(conn);
}

/* Close the connection but still available for re-use */
void
conn_close(conn_t *conn) {
	conn_lock(conn);

	logline(log_DEBUG_, CONN_ID " closing", conn_id(conn));

	/* Already closed? */
	if (conn->sock == INVALID_SOCKET) {
		logline(log_DEBUG_, CONN_ID " Already closed", conn_id(conn));
		conn_unlock(conn);
		return;
	}

	/* Don't want to hear from this socket any further */
	conn_eventsA(conn, CONN_POLLNONE);

	/* Make the socket temporarily blocking */
	conn_set_nonblocking(conn);

	/* Shutdown the socket */
	shutdown(conn->sock, SHUT_RDWR);

	/* Close it */
	closesocket(conn->sock);
	conn->sock = INVALID_SOCKET;

	/* Set the state to unused */
	conn_set_state(conn, CONN_UNUSED);

	/* Nothing sent or received */
	conn->last_sent	= 0;
	conn->last_recv	= 0;

	/* Nothing to send or receive */
	buf_empty(&conn->recv);
	buf_empty(&conn->send);
	buf_empty(&conn->send_headers);

#ifdef CONN_SSL
	if (conn->ssl) {
		/* This also free's the BIOs */
		SSL_free(conn->ssl);
		conn->ssl = NULL;
		conn->ssl_bio_in = NULL;
		conn->ssl_bio_out = NULL;
	}

	memzero(conn->ssl_in, sizeof conn->ssl_in);
	conn->ssl_in_len = 0;

	memzero(conn->ssl_out, sizeof conn->ssl_out);
	conn->ssl_out_len = 0;
#endif /* CONN_SSL */

	conn_unlock(conn);
}

static bool
conn_is_eofA(conn_t UNUSED *conn) {
	return (false);
#if 0
	/*
	 * XXX: Not enabled as needs more testing for correctness
         *      with (block/non-blockng sockets
	 */
	int	r;
	char	buf[2];
	bool	ret;

	logline(log_DEBUG_, CONN_ID " checking for EOF", conn_id(conn));

	/* Async sockets will receive EOF at poll() time */
	if (conn->connset != NULL) {
		logline(log_DEBUG_, CONN_ID " checking for EOF (async)", conn_id(conn));
		return (false);
	}

	/* Peek if there is something */
	r = recv(conn->sock, buf, sizeof buf, MSG_PEEK | MSG_NOSIGNAL | MSG_DONTWAIT);

	/* Are we still connected? */
	ret = (r <= 0 && errno == ENOTCONN);

	logline(log_DEBUG_, CONN_ID " checking for EOF (%s)", conn_id(conn),yesno(ret));

	return (ret);
#endif
}

bool
conn_is_eof(conn_t *conn) {
	bool	ret;
	
	conn_lock(conn);
	ret = conn_is_eofA(conn);
	conn_unlock(conn);
	return (ret);
}

/* What do we want to hear? (Mutex locked by caller) */
void
conn_eventsA(conn_t *conn, uint16_t events) {
	assert(conn_is_valid(conn));

	/*
	 * We allow sockets to work without a connset
	 * they are synchronous then though
	 */
	if (conn->connset == NULL)
		return;

	/* Nothing to do? */
        if (conn->wntevents == events)
		return;

	connset_lock(conn->connset);

	/* Currently monitoring for something? */
	if ((conn->wntevents & CONN_POLLIN) !=
	          (events & CONN_POLLIN)) {
		/* Remove the bit? */
		if (events & CONN_POLLIN)
			FD_SET(conn->sock, &conn->connset->fd_read);
		else
			FD_CLR(conn->sock, &conn->connset->fd_read);
	}

	if ((conn->wntevents & CONN_POLLOUT) !=
	          (events & CONN_POLLOUT)) {
		/* Remove the bit? */
		if (events & CONN_POLLOUT)
			FD_SET(conn->sock, &conn->connset->fd_write);
		else
			FD_CLR(conn->sock, &conn->connset->fd_write);
	}

	connset_unlock(conn->connset);

	logline(log_DEBUG_, CONN_ID " (A)", conn_id(conn));

	/*
	 * Place currently inactive (wntevents == 0)
	 * sockets on the active queue (wntevents != 0)
	 */
	if (conn->wntevents == 0 && events != 0) {
		logline(log_DEBUG_, CONN_ID " making active", conn_id(conn));

		/* remove from inactive */
		list_remove_l(&conn->connset->inactive, &conn->node);

		/* add it to active */
		list_addtail_l(&conn->connset->active, &conn->node);
		conn->connset_l = &conn->connset->active;

	} else if (conn->wntevents != 0 && events == 0) {
		logline(log_DEBUG_, CONN_ID " making inactive", conn_id(conn));

		/* remove from active or ready */
		if (conn->connset_l) {
			list_remove_l(conn->connset_l, &conn->node);
			conn->connset_l = NULL;
		}

		/* add it to inactive */
		list_addtail_l(&conn->connset->inactive, &conn->node);
		conn->connset_l = &conn->connset->inactive;
	}
	/* wntevents == events is handled above as a noop */
	/* wntevents != 0 && events != 0 would mean stay in the same list */

	logline(log_DEBUG_, CONN_ID " (B)", conn_id(conn));

	/* They match now */
	conn->wntevents = events;

	logline(log_DEBUG_, CONN_ID " events are now: %s %s",
		conn_id(conn),
		conn_wnt_in(conn)	? "IN" : ".",
		conn_wnt_out(conn)	? "OUT" : ".");

	if (events != 0) {
		/* It is an active socket */
		logline(log_DEBUG_, CONN_ID " active socket", conn_id(conn));

/* Windows does not use the highest fd param, it is there for compat only */
#ifndef _WIN32
		/* Make sure we have the right Highest FD */
		if (conn->sock > conn->connset->hifd) {
			logline(log_DEBUG_,
				CONNS_ID " New high FD: %d, " CONN_ID,
				conn->connset->id,
				(unsigned int)conn->sock,
				conn_id(conn));
			conn->connset->hifd = conn->sock;
		} else {
			logline(log_DEBUG_,
				CONNS_ID " Old high FD: %d, " CONN_ID " = %d]",
				conn->connset->id,
				conn->connset->hifd,
				conn_id(conn),
				(unsigned int)conn->sock);
		}
#endif
	} else {
		/* No events, thus do not check it */
		logline(log_DEBUG_, CONN_ID " inactive socket", conn_id(conn));
	}
}

void
conn_events(conn_t *conn, uint16_t events) {
	conn_lock(conn);
	conn_eventsA(conn, events);
	conn_unlock(conn);
}

#ifdef CONN_SSL
/* returns: true = done, false = not done */
/* Internal only, does not lock */
static bool
conn_ssl_flush(conn_t *conn) {
	ssize_t r;

	assert(conn_is_valid(conn));

	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

	/* Nothing to do? */
	if (!conn->ssl || conn->ssl_out_len == 0) {
		logline(log_DEBUG_, CONN_ID " nothing to do", conn_id(conn));
		return (true);
	}

	/* Send the crypted bits over the wire */
	r = send(conn->sock, conn->ssl_out, conn->ssl_out_len, MSG_NOSIGNAL);
	if (r <= -1) {
		logline(log_NOTICE_, CONN_ID " ERR %" PRId64 " (SSL)",
			conn_id(conn), r);
		return (false);
	}

	if (((uint64_t)r) != conn->ssl_out_len) {
		/*
		 * Didn't write it all yet, thus shove it up
		 * and try again in the next round
		 */
		uint64_t left;

		assert(r < conn->ssl_out_len);
		left = conn->ssl_out_len - r;

		logline(log_DEBUG_,
			CONN_ID " sent %" PRIu64 ", but %" PRIu64 " left",
			conn_id(conn), r, left);

		memmove(&conn->ssl_out, &conn->ssl_out[r], left);

		conn->ssl_out_len = left; 

		/* Our work is done for now, try again later */
		return (false);
	}

	/* Done writing all our SSL data */
	conn->ssl_out_len = 0;
	logline(log_DEBUG_, CONN_ID " done %" PRIu64, conn_id(conn), r);

	return (true);
}

static void
conn_ssl_bio_write(conn_t *conn) {
	int rc;

	logline(log_DEBUG_, CONN_ID " in: %u", conn_id(conn), conn->ssl_in_len);

	/*
	 * socket -> ssl_in[c] - BIO_write -> SSL_read -> data[p];
	 *
	 * We read from the socket crypted data into ssl_in,
	 * thus write towards OpenSSL which can then decrypt it
	 */
	rc = BIO_write(conn->ssl_bio_in, &conn->ssl_in, conn->ssl_in_len);
	logline(log_DEBUG_, CONN_ID " BIO_write = %d", conn_id(conn), rc);

	/*
	 * The return code includes the amount of data written by OpenSSL
	 * Which is also why we attempt to write 0 data streams as OpenSSL
	 * adds extra bytes for the crypto.
	 */
	if (rc <= 0) {
		/* Nothing done */
		return;
	}

	logline(log_DEBUG_,
		CONN_ID " BIO_write(%u) resulted in %u written",
		conn_id(conn), conn->ssl_in_len,
		(unsigned int)rc);

	/*
	 * All written out, impartial writes never happen
	 * (at least there is no way the API supports them...)
	 */
	conn->ssl_in_len = 0;

	if (!SSL_is_init_finished(conn->ssl)) {
		/*
		 * If we are listening we do not connect
		 * If we connect, we simply let the loop handle it
		 */
		if (conn->last_connect == 0) {
			logline(log_DEBUG_, "Attempting SSL Handshake");
			rc = SSL_do_handshake(conn->ssl);
		}
	} else {
		logline(log_DEBUG_, "Attempting SSL Read");
		rc = SSL_read(conn->ssl, buf_bufend(&conn->recv),
			      conn_buffer_left(conn));

		if (rc > 0) {
			buf_added(&conn->recv, rc);

			logline(log_DEBUG_,
				CONN_ID " got additional %u, "
				"total = %" PRIu64,
				conn_id(conn), rc, buf_cur(&conn->recv));
		}
	}

	if (rc <= 0) {
		conn_ssl_err(conn, "SSL_read error");
	}
}

static void
conn_ssl_bio_read(conn_t *conn) {
	int rc;

	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

	/*
	 * data[p] -> SSL_write() -> BIO_read -> ssl_out[c] -> socket 
	 *
	 * We passed our buffer to SSL_write() which crypts data that
	 * the result of which ends up in bio_out,
	 * thus read it and then send it out over the socket by doing
	 * a conn_ssl_flush();
	 */
	rc = BIO_read(conn->ssl_bio_out,
		       &conn->ssl_out[conn->ssl_out_len],
		       sizeof conn->ssl_out - conn->ssl_out_len);
	logline(log_DEBUG_, CONN_ID " BIO_read = %d", conn_id(conn), rc);
	if (rc > 0) {
		/* We got data that needs flushing */
		conn->ssl_out_len += rc;

		logline(log_DEBUG_,
			CONN_ID " BIO_read() = %u => %u",
			conn_id(conn), (unsigned int)rc, conn->ssl_out_len);

		conn_ssl_flush(conn);
	}
}

static void
conn_ssl_bio(conn_t *conn) {

	logline(log_DEBUG_, CONN_ID ", ...", conn_id(conn));

	conn_ssl_bio_write(conn);
	conn_ssl_bio_read(conn);

	logline(log_DEBUG_, CONN_ID " in: %u/%u, out: %u/%u",
		conn_id(conn),
		conn->ssl_in_len, (unsigned int)buf_cur(&conn->recv),
		conn->ssl_out_len, (unsigned int)buf_cur(&conn->send));
}

static long
conn_ssl_bio_cb(BIO *b, int oper, const char UNUSED *argp,
                        int UNUSED argi, long UNUSED argl, long retvalue)
{
	conn_t		*conn = (conn_t *)BIO_get_callback_arg(b);
	const char	*op = "???";
	int		soper = oper & 0x0f;

	switch (soper) {
	case BIO_CB_FREE:
		op = "Free";
		break;
	case BIO_CB_READ:
		op = "Read";
		break;
	case BIO_CB_WRITE:
		op = "Write";
		break;
	case BIO_CB_PUTS:
		op = "Puts";
		break;
	case BIO_CB_GETS:
		op = "Gets";
		break;
	case BIO_CB_CTRL:
		op = "Control";
		break;
	default:
		op = "Unknown";
		break;
	}

	logline(log_DEBUG_, CONN_ID " oper = %u / %s ret: %ld, %s %s",
		conn_id(conn), oper, op, retvalue,
		(b == conn->ssl_bio_in  ? "IN"  : ".."),
		(b == conn->ssl_bio_out ? "OUT" : "..."));

	/* Flush our socket */
	conn_ssl_flush(conn);

	if (oper == BIO_CB_READ && b == conn->ssl_bio_in) {
		logline(log_DEBUG_, CONN_ID " Attempting BIO Write", conn_id(conn));
		conn_ssl_bio_write(conn);
	}

	if (	(oper == (BIO_CB_WRITE|BIO_CB_RETURN)) &&
		b == conn->ssl_bio_out) {

		/* Read a bit */
		logline(log_DEBUG_, CONN_ID " Attempting BIO Read", conn_id(conn));
		conn_ssl_bio_read(conn);
	}

	return (retvalue);
}
#endif /* CONN_SSL */

/* Locked by caller */
int
conn_recvA(conn_t *conn) {
	uint64_t	len;
	ssize_t		r;

	assert(conn_is_valid(conn));
	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

#ifdef CONN_SSL
	if (conn->ssl) {
		len = sizeof conn->ssl_in - conn->ssl_in_len;
		logline(log_DEBUG_, CONN_ID " ssl left = %" PRIu64, conn_id(conn), len);
		thread_setstate(thread_state_io_read);
		r = recv(conn->sock, &conn->ssl_in[conn->ssl_in_len],
			 len, MSG_NOSIGNAL);
		thread_setstate(thread_state_running);
	} else {
#endif /* CONN_SSL */
		len = conn_buffer_left(conn);
		logline(log_DEBUG_, CONN_ID " left = %" PRIu64, conn_id(conn), len);
		thread_setstate(thread_state_io_read);
		r = recv(conn->sock, buf_bufend(&conn->recv),
			len, MSG_NOSIGNAL);
		thread_setstate(thread_state_running);
#ifdef CONN_SSL
	}
#endif

	/* Orderly shutdown? */
	if (r == 0) {
		logline(log_DEBUG_,
			CONN_ID " EOF (len=%" PRIsizet ")",
			conn_id(conn), r);
		return (-1);	/* Remote end closed socket */
	}

	if (r <= -1) {
		if (errno == EAGAIN) {
			logline(log_DEBUG_,
				CONN_ID " EAGAIN (len=%" PRIsizet ")",
				conn_id(conn), r);
			return (0);
		}

		logline(log_DEBUG_,
			CONN_ID " ERR (len=%" PRIsizet ")",
			conn_id(conn), r);
		return (-1);
	}

	conn->last_recv = gettime();

#ifdef CONN_SSL
	if (conn->ssl) {
		logline(log_DEBUG_, CONN_ID " ssl received %" PRIu64, conn_id(conn), r);
		conn->ssl_in_len += r;

		conn_ssl_bio(conn);

	} else {
#endif
		uint64_t cur = buf_cur(&conn->recv);

		buf_added(&conn->recv, r);

		logline(log_DEBUG_,
			CONN_ID " got additional %" PRIsizet ", "
			"total = %" PRIu64,
			conn_id(conn), r, buf_cur(&conn->recv));

		dumppacket(	LOG_DEBUG,
				(uint8_t *)&buf_buffer(&conn->recv)[cur], r);
#ifdef CONN_SSL
	}
#endif

	/* recv() doesn't return a null-terminated string, thus do it */
	*buf_bufend(&conn->recv) = '\0';

	/* Return the amount  bytes in the buffer */
	logline(log_DEBUG_, CONN_ID " return %" PRIu64,
		conn_id(conn), buf_cur(&conn->recv));

	return (buf_cur(&conn->recv));
}

int
conn_recv(conn_t *conn) {
	int ret;

	conn_lock(conn);
	ret = conn_recvA(conn);
	conn_unlock(conn);

	return (ret);
}

int
conn_recvline(conn_t *conn, char *buf, unsigned int buflen) {
	char		*s;
	unsigned int	len;
	int		i;

	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

	conn_lock(conn);

	/* Forever and ever */
	while (true) {

		/* Already something in our buffer? */
		if (buf_cur(&conn->recv) > 0) {

			/* Check for \n */
			s = strchr(buf_buffer(&conn->recv), '\n');

			/* There already is a full line in the buffer */
			if (s != NULL) {
				len = (s - buf_buffer(&conn->recv)) + 1;

				/* Does it not fit? */
				if (len > buflen) {
					logline(log_DEBUG_,
						CONN_ID " line does not fit "
						"%u > %u",
						conn_id(conn),
						len, buflen);
					conn_unlock(conn);
					return (-ENOSPC);
				}

				/* Pass the string to the caller's buffer */
				memcpy(buf, buf_buffer(&conn->recv), len);

				/* Remove the string from our buffer */
				buf_shift(&conn->recv, len);

				/* Strip possible \r's */
				while (len > 1 && buf[len-2] == '\r') {
					buf[len-2] = '\n';
					buf[len-1] = '\0';
					len--;
				}

				/* Terminate it for sure */
				buf[len] = '\0';

				conn_unlock(conn);
				return (len);
			}
		}

		/* non-blocking socket? Then we are done */
		if (conn->connset != NULL) {
			logline(log_DEBUG_,
				CONN_ID " buffer empty, please conn_recv() more",
				conn_id(conn));
			break;
		}

		logline(log_DEBUG_, CONN_ID " trying to get more", conn_id(conn));

		/* Receive more */
		i = conn_recvA(conn);
		if (i == 0) {
			/* Blocking socket, thus cannot happen */
			assert(false);
			break;
		} else if (i < 0) {
			/* Connection got closed etc */
			conn_unlock(conn);
			return (i);
		}
	}

	conn_unlock(conn);
	return (0);
}

void
conn_set_flush_hook(conn_t *conn, conn_flush_hook hook, void *data) {
	conn_lock(conn);
	conn->flush_hook = hook;
	conn->flush_data = data;
	conn_unlock(conn);
}

void
conn_unset_flush_hook(conn_t *conn) {
	conn_lock(conn);
	conn->flush_hook = NULL;
	conn->flush_data = NULL;
	conn_unlock(conn);
}

#ifdef CONN_SSL
static bool
conn_ssl_send(conn_t *conn, const char *buf, uint64_t *len) {
	int	rc;

	logline(log_DEBUG_, CONN_ID " %u", conn_id(conn), (unsigned int)*len);

	/* Check if the BIOs need attention */
	conn_ssl_bio(conn);

	/* Write cleartext to the SSL which stores it in the bio crypted */
	rc = SSL_write(conn->ssl, buf, *len);

	/* Map SSL errors to APR errors */
	if (rc <= 0) {
		conn_ssl_err(conn, "SSL_write error");
		return (false);
	}

	if ((unsigned int)rc != *len) {
		logline(log_DEBUG_, CONN_ID " SSL_write %u/%u",
			conn_id(conn), rc, (unsigned int)*len);
	}

	/* The amount that was written */
	*len = rc;

	/* Check if the BIOs need attention */
	conn_ssl_bio(conn);

	return (true);
}

static bool
conn_ssl_sendv(conn_t *conn, const struct iovec *vec,
	       unsigned int nvec, uint64_t *len)
{
	bool		ret;
	uint64_t	written = 0;
	int		i;

	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

	for (i = 0; i < nvec; i++) {
		uint64_t rd = vec[i].iov_len;

		if (rd == 0)
			continue;

		ret = conn_ssl_send(conn, vec[i].iov_base, &rd);
		if (!ret) {
			*len = written;
			return (false);
		}

		written += rd;
	}

	*len = written;

	logline(log_DEBUG_, CONN_ID " wrote %" PRIu64, conn_id(conn), *len);

	return (true);
}
#endif /* CONN_SSL */

/* Flush a bit more of the buffer towards the client */
bool
conn_flush(conn_t *conn) {
	ssize_t		r;
	uint64_t	len, wlen;

	logline(log_DEBUG_, CONN_ID "", conn_id(conn));

	conn_lock(conn);

#ifdef CONN_SSL
	if (!conn_ssl_flush(conn)) {
		/* Still need to flush the SSL buffer */
		/* Thus don't do anything else here yet */
		logline(log_DEBUG_, CONN_ID " SSL flush needed", conn_id(conn));
		conn_unlock(conn);
		return (true);
	}
#endif /* CONN_SSL */

	len = buf_cur(&conn->send) + buf_cur(&conn->send_headers);

	if (!conn_is_connected(conn) || conn_is_eofA(conn)) {
		logline(log_DEBUG_, CONN_ID " not connected", conn_id(conn));
		conn_unlock(conn);
		return (false);
	}

	/* Nothing to flush */
	if (len == 0) {
		logline(log_DEBUG_, CONN_ID " nothing to flush", conn_id(conn));
		/* Nothing to flush thus continue polling for incoming */
		conn_eventsA(conn, CONN_POLLIN);
		conn_unlock(conn);
		return (true);
	}

	conn->last_sent = gettime();

	/* Call the flush hook */
	if (conn->flush_hook) {
		if (buf_cur(&conn->send_headers) > 0) {
			conn->flush_hook(conn->flush_data,
					 conn_id(conn), true,
					 buf_buffer(&conn->send_headers),
					 buf_cur(&conn->send_headers));
		}

		if (buf_cur(&conn->send) > 0) {
			conn->flush_hook(conn->flush_data,
					 conn_id(conn), false,
					 buf_buffer(&conn->send),
					 buf_cur(&conn->send));
		}
	}

	if (buf_cur(&conn->send_headers) > 0) {
		struct iovec	iovec[2];
		unsigned int	iolen;

		/* Add separating when we didn't yet \n */
		assert((buf_cur(&conn->send) +
			buf_cur(&conn->send_headers)) != 0);

		if (conn->add_contentlen &&
		    (conn->real_contentlen > 0 || buf_cur(&conn->send) > 0)) {
			logline(log_DEBUG_,
				CONN_ID " Outputting Content-Length: %" PRIu64,
				conn_id(conn), buf_cur(&conn->send));

#ifdef NETWORK_DETAILS
			conn_addheaderf(conn,
				"CONN-Content-CONN-Length: %" PRIu64 "\r\n",
				buf_cur(&conn->send));
#endif

			if (conn->real_contentlen != 0) {
				logline(log_DEBUG_, CONN_ID
					" Real Content-Length: %" PRIu64,
					conn_id(conn), conn->real_contentlen);
			}

			conn_addheaderf(conn,
				"Content-Length: %" PRIu64 "\r\n",
				conn->real_contentlen > 0 ?
					conn->real_contentlen :
					buf_cur(&conn->send));

			/* Reset it to avoid re-use */
			conn->real_contentlen = 0;
		}

		/* Separate header from body */
		conn_addheader(conn, "\r\n");

		logline(log_DEBUG_,
			"Full HEADERs (%" PRIu64 " vs %" PRIsizet ")",
			buf_cur(&conn->send_headers),
			strlen(buf_buffer(&conn->send_headers)));
		logline(log_DEBUG_, "8<-----------");
		logline(log_DEBUG_, "%s", buf_buffer(&conn->send_headers));
		logline(log_DEBUG_, "----------->8\n");

		/* The chunks to send */
		iovec[0].iov_base = buf_buffer(&conn->send_headers);
		iovec[0].iov_len = buf_cur(&conn->send_headers);
		iovec[1].iov_base = buf_buffer(&conn->send);
		iovec[1].iov_len = buf_cur(&conn->send);

		/* Total length */
		len = iovec[0].iov_len + iovec[1].iov_len;

		/* Sometimes we do not have content thus we skip that one */
		iolen = iovec[1].iov_len > 0 ? 2 : 1;

		logline(log_DEBUG_, CONN_ID " Flushing %" PRIu64 " (h)",
			conn_id(conn), len);

#ifdef CONN_SSL
		if (conn->ssl) {
			r = conn_ssl_sendv(conn, iovec, iolen, &wlen);
		} else {
#endif
			thread_setstate(thread_state_io_write);
			r = writev(conn->sock, iovec, iolen);
			thread_setstate(thread_state_running);
			wlen = r;
#ifdef CONN_SSL
		}
#endif
	} else {
		wlen = buf_cur(&conn->send);
		logline(log_DEBUG_, CONN_ID " Flushing %" PRIu64, conn_id(conn), len);

#ifdef CONN_SSL
		if (conn->ssl) {
			r = conn_ssl_send(conn, buf_buffer(&conn->send), &wlen);
		} else {
#endif
			assert(conn_is_valid(conn));
			thread_setstate(thread_state_io_write);
			r = send(conn->sock, buf_buffer(&conn->send), wlen,
				 MSG_NOSIGNAL);
			thread_setstate(thread_state_running);
			wlen = r;
#ifdef CONN_SSL
		}
#endif
	}

	if (r <= -1) {
		logline(log_NOTICE_, CONN_ID " Flushing error = %" PRIsizet,
			conn_id(conn), r);
		conn_unlock(conn);
		return (false);
	}

	if (wlen == len) {
		/* Nothing further to send */
		buf_empty(&conn->send);
		buf_empty(&conn->send_headers);

		/* We always want to know about this */
		conn_eventsA(conn, CONN_POLLIN);
	} else {
		/* Headers will go first */
		if (buf_cur(&conn->send_headers) > 0) {
			if (wlen > buf_cur(&conn->send_headers)) {
				/* Done with the headers */
				wlen -= buf_cur(&conn->send);
				buf_empty(&conn->send_headers);
			} else {
				/* Move rest to the front of the buffer */
				buf_shift(&conn->send_headers, wlen);
				wlen = 0;
			}
		}

		/* Bytes left from the normal buffer? */
		if (wlen > 0) {
			/* Move the rest to the front of the buffer */
			buf_shift(&conn->send, wlen);
		}

		/* Try to get it out there */
		conn_eventsA(conn, CONN_POLLIN | CONN_POLLOUT);
	}

	logline(log_DEBUG_, CONN_ID " left %" PRIu64,
		conn_id(conn), buf_cur(&conn->send));

	conn_unlock(conn);
	return (true);
}

/* Not locking mutex as buf handles that */
/* Callers might have locked the conn mutex */
bool
conn_addheader(conn_t *conn, const char *txt) {
	return (buf_put(&conn->send_headers, txt));
}

/* Not locking mutex as buf handles that */
/* Callers might have locked the conn mutex */
bool
conn_addheaderf(conn_t *conn, const char *fmt, ...) {
        va_list		ap;
	bool		ret;
	uint64_t	cur;

        va_start(ap, fmt);

	cur = buf_cur(&conn->send_headers);
	ret = buf_vprintf(&conn->send_headers, fmt, ap);

	logline(log_DEBUG, __func__, CONN_ID " (len=%" PRIu64 ") %s",
		conn_id(conn), buf_cur(&conn->send_headers) - cur,
		&buf_buffer(&conn->send_headers)[cur]);

	va_end(ap);

	return (ret);
}

bool
conn_putl(conn_t *conn, const char *txt, unsigned int len) {
	bool		ret;
	uint64_t	cur;

	if (len == 0)
		return (true);

	conn_lock(conn);

	cur = buf_cur(&conn->send);
	ret = buf_putl(&conn->send, txt, len);

	if (ret) {
		logline(log_DEBUG_, CONN_ID ": %u", conn_id(conn), len);

		dumppacket(	LOG_DEBUG,
				(uint8_t *)&buf_buffer(&conn->send)[cur],
				buf_cur(&conn->send) - cur);

		/* Only autoflush when we don't have headers set */
		if (buf_cur(&conn->send_headers) == 0) {
			conn_eventsA(conn, CONN_POLLIN | CONN_POLLOUT);
		}
	}

	conn_unlock(conn);

	return (ret);
}

bool
conn_put(conn_t *conn, const char *txt) {
	unsigned int	len = strlen(txt);

	return (conn_putl(conn, txt, len));
}

bool
conn_copy(conn_t *in, conn_t *out) {
	bool ret;

	/* Copy the received buffer from the in to the out */
	ret = conn_putl(out, conn_buffer(in), conn_buffer_cur(in));

	/* Input has been processed */
	conn_buffer_empty(in);

	return (ret);
}

uint64_t
conn_copym(conn_t *in, conn_t *out, uint64_t max) {
	uint64_t	len;
	bool		ret;

	/* Only copy upto 'max' bytes */
	len = conn_buffer_cur(in);
	if (max < len) len = max;

	/* Copy the received buffer from the in to the out */
	ret = conn_putl(out, conn_buffer(in), len);

	/* All okay */
	if (ret) {
		/* Input has been processed */
		conn_buffer_shift(in, len);
	}

	return (ret ? len : 0);
}

bool
conn_vprintf(conn_t *conn, const char *fmt, va_list ap) {
	bool		ret;
	uint64_t	cur;

	assert(conn_is_valid(conn));

	conn_lock(conn);

	cur = buf_cur(&conn->send);
	ret = buf_vprintf(&conn->send, fmt, ap);

	if (ret) {
		logline(log_DEBUG_, CONN_ID "", conn_id(conn));

		dumppacket(	LOG_DEBUG,
				(uint8_t *)&buf_buffer(&conn->send)[cur],
				buf_cur(&conn->send) - cur);

		/* Only autoflush when we don't have headers set */
		if (buf_cur(&conn->send_headers) == 0) {
			conn_eventsA(conn, CONN_POLLIN | CONN_POLLOUT);
		}
	}

	conn_unlock(conn);
	return (ret);
}

/* Not locking mutex as conn_vprintf() does that */
bool
conn_printf(conn_t *conn, const char *fmt, ...) {
        va_list	ap;
	bool	ret;

        va_start(ap, fmt);
	ret = conn_vprintf(conn, fmt, ap);
	va_end(ap);

	return (ret);
}

/*
 * Create a listen socket
 * Might create multiple conn structures due to multiple sockets
 * No mutex locking needed here as only one thread can access it
 */
bool
conn_create_listen(connset_t *connset,
		   const char *hostname, uint32_t protocol, uint32_t port)
{
	struct addrinfo		hints, *res = NULL, *ressave = NULL;
	socket_t		sock = INVALID_SOCKET;
	char			buf[64];
	conn_t			*conn;
	unsigned int		type, count = 0;
	int			n, on;
	char			service[32];
	const char		*errfunc;

	/* Require a conlset */
	assert(connset != NULL);

	type = (protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM);
	snprintf(service, sizeof service, "%u", port);

	logline(log_DEBUG_,
		"hostname = %s, protocol = %u, port = %u, type = %u",
		hostname, protocol, port, type);

	/* AI_PASSIVE flag: the resulting address is used to bind
	   to a socket for accepting incoming connections.
	   So, when the hostname==NULL, getaddrinfo function will
	   return one entry per allowed protocol family containing
	   the unspecified address for that family. */

	memzero(&hints, sizeof hints);
	hints.ai_flags    = AI_PASSIVE;
	hints.ai_family   = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;

	n = getaddrinfo(hostname, service, &hints, &res);
	if (n < 0) {
		logline(log_NOTICE_, "getaddrinfo() failed: %s", gai_strerror(n));
		return (false);
	}

	ressave = res;

	while (res) {
		/* No errors this round yet */
		errfunc = NULL;

		sock = socket(res->ai_family,
#ifdef _LINUX
			      SOCK_CLOEXEC |
#endif
			      res->ai_socktype,
			      res->ai_protocol);

		if (sock != INVALID_SOCKET) {
#ifndef _LINUX
#ifndef _WIN32
			/* Ensure FD_CLOEXEC is set for platforms without SOCK_CLOEXEC */
			/* No fork() on Windows, thus not needed there */
			fcntl(sock, F_SETFD, FD_CLOEXEC);
#endif
#endif

			/*
			 * Reuse the address+port, handy when quickly
			 * restarting the tool and previous connections
			 * still linger in half open/closed TCP state.
			 */
			on = 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
				   (const char *)&on, sizeof on);
			on = 1;
			setsockopt(sock, SOL_SOCKET, SO_REUSEPORT,
				   (const char *)&on, sizeof on);

			/* Only bind to IPv6, not also IPv4 compat */
			if (res->ai_family == AF_INET6) {
				on = 1;
				setsockopt(sock, SOL_IPV6, IPV6_V6ONLY,
					  (const char *)&on, sizeof on);
			}

			if (bind(sock, res->ai_addr,
				 (int)res->ai_addrlen) == 0)
			{
				if (res->ai_socktype == SOCK_DGRAM ||
				    listen(sock, LISTEN_QUEUE) == 0) {
					inet_rtop(res, buf, sizeof buf);

					logline(log_DEBUG_, "Listening on %s",
						buf);

					conn = (conn_t *)mcalloc(sizeof *conn,
								 "conn");
					if (!conn) {
						logline(log_CRIT_,
							"No mem for conn");
						break;
					}

					if (!conn_init(conn, NULL)) {
						logline(log_CRIT_,
							"Conn init failed");
						break;
					}

					conn->sock = sock;
					conn->protocol = protocol;
					conn->port = port;

					/* Always non-blocking */
					conn_set_nonblocking(conn);

					conn_set_connset(conn, connset);
					conn_eventsA(conn, CONN_POLLIN);

					/* Mark it as listening */
					conn_set_state(conn, CONN_LISTENING);

					/* Listening on one */
					count++;
				} else {
					errfunc = "listen";
				}
			} else {
				errfunc = "bind";
			}
		} else {
			errfunc = "socket";
		}

		if (errfunc) {
			inet_rtop(res, buf, sizeof buf);

			logline(log_NOTICE_, "Couldn't %s() on %s", errfunc, buf);

			/* Make sure we close it */
			if (sock != INVALID_SOCKET) {
				closesocket(sock);
			}
		}

		/* Next combination */
		res = res->ai_next;
	}

	if (ressave)
		freeaddrinfo(ressave);

	return (count == 0 ? false : true);
}

/*
 * Create a connection to a host:service.
 * We use connected sockets even for datagram connections
 * These are non-blocking and thus connset_poll() has to
 * determine when it is actually connected
 */
bool
conn_create_connection(conn_t *conn, const char *hostname,
		       uint32_t protocol, uint32_t port,
		       connset_t *connset) {
	struct addrinfo		hints, *res, *ressave = NULL;
	char			service[32], buf[128];
	unsigned int		type;
	int			n;

	assert(conn);
	assert(hostname != NULL);
	assert(port != 0);

	snprintf(service, sizeof service, "%u", port);

	conn_lock(conn);

	logline(log_DEBUG_, CONN_ID " (%s:%s)", conn_id(conn), hostname, service);

	type = (protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM);

	/* Last time we attempted a connection */
	conn->last_connect = gettime();

	memzero(&hints, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = type;
	hints.ai_protocol = protocol;
	hints.ai_flags = AI_ADDRCONFIG;

	n = getaddrinfo(hostname, service, &hints, &res);

	if (n < 0)
	{
		logline(log_NOTICE_, "\"%s\":\"%s\" - getaddrinfo error: [%s]",
			hostname, service, gai_strerror(n));
		conn_unlock(conn);
		return (false);
	}

	ressave = res;

	while (res) {
		/* Get a human readable string */
		inet_rtop(res, buf, sizeof buf);

		logline(log_DEBUG_, "Attempting connect to %s:%u:%u (%s)",
					hostname, protocol, port, buf);

		conn->sock = socket(res->ai_family,
#ifdef _LINUX
				    SOCK_CLOEXEC |
#endif
			            res->ai_socktype,
			            res->ai_protocol);

		if (conn->sock != INVALID_SOCKET) {
#ifndef _LINUX
#ifndef _WIN32
			/*
			 * Ensure FD_CLOEXEC is set for platforms
			 * without SOCK_CLOEXEC
			 */
			fcntl(conn->sock, F_SETFD, FD_CLOEXEC);
#endif
#endif
			/* To block or to not to block? */
			if (connset)
				conn_set_nonblocking(conn);
			else
				conn_set_blocking(conn);

			n = connect(conn->sock, res->ai_addr,
				    (int)res->ai_addrlen);

			if (	n == 0 ||
				(connset && n == -1 && errno == EINPROGRESS))
			{
				/* Connected */
				logline(log_DEBUG_, "Connected (%s:%u:%u)%s",
					hostname, protocol, port,
					n == 0 ? "" : " [still trying]");

				/* New state */
				conn_set_state(conn, n == 0 ?
						CONN_CONNECTED :
						CONN_CONNECTING);

				/* Our protocol */
				conn->protocol = protocol;

				/* Our port */
				conn->port = port;

				/* Swap over to the given connset */
				conn_set_connset(conn, connset);

				/* We want to know all about this socket */
				conn_eventsA(conn, CONN_POLLIN | CONN_POLLOUT);

				break;
			} else {
				logline(log_NOTICE_,
					"Failed to connect to %s %d/%d",
					buf, errno, EINPROGRESS);
				closesocket(conn->sock);
				conn->sock = INVALID_SOCKET;
			}
		} else {
			logline(log_ERR_, "Couldn't get a socket for %s", buf);
		}

		res = res->ai_next;
	}

	conn_unlock(conn);

	if (ressave)
		freeaddrinfo(ressave);

	return (conn_is_valid(conn));
}

/*
 * Create a connection to a host:service.
 * Note that this is a blocking version
 * It produces a nonblocking socket when a connset is provided
 * but blocks for the duration of the connect
 */
bool
conn_connect(conn_t *conn, const char *host,
	     unsigned int protocol, unsigned int port) {

	return (conn_create_connection(conn, host, protocol, port, NULL));
}

bool
conn_accept(conn_t *conn, conn_t *lconn, void *clientdata) {
	char		address[256];
	uint32_t	protocol, port;

	assert(conn);
	assert(conn->sock == INVALID_SOCKET);

	assert(lconn);
	assert(lconn->sock != INVALID_SOCKET);

	/* Setup the context */
	conn_lock(lconn);
	conn_lock(conn);

	/* Mark that it is accepting a new connection */
	conn_set_state(conn, CONN_ACCEPTING);

	/* Accept the socket */
#ifdef _LINUX
	conn->sock = accept4(lconn->sock, NULL, 0, SOCK_CLOEXEC);
#else
	conn->sock = accept(lconn->sock, NULL, 0);
#endif

	conn_unlock(lconn);

	if (conn->sock == INVALID_SOCKET) {
		conn_unlock(conn);
		logline(log_ERR_, CONN_ID " failed accept", conn_id(conn));
		return (false);
	}

#ifndef _LINUX
#ifndef _WIN32
	/* Ensure FD_CLOEXEC is set for platforms without accept4() */
	fcntl(conn->sock, F_SETFD, FD_CLOEXEC);
#endif
#endif

	/* Take over the connset from the listening socket */
	conn_set_connset(conn, lconn->connset);

	conn->protocol	= lconn->protocol;
	conn->port	= lconn->port;
	conn->clientdata= clientdata;

	/* We want to know all about this socket */
	conn_eventsA(conn, CONN_POLLIN | CONN_POLLOUT);

	conn_unlock(conn);

	conn_getinfo(conn, false, address, sizeof address, &protocol, &port);

	logline(log_DEBUG_,
		CONN_ID " accepted connection from %s, proto %u, port %u",
		conn_id(conn), address, protocol, port);

	conn_getinfo(conn, true, address, sizeof address, &protocol, &port);

	logline(log_DEBUG_,
		CONN_ID " accepted connection towards %s, proto %u, port %u",
		conn_id(conn), address, protocol, port);

	conn_set_state(conn, CONN_CONNECTED);

	return (true);
}

bool
conn_getinfo(conn_t *conn, bool local, char *hostname, unsigned int hlen,
		uint32_t *proto, uint32_t *port)
{
	struct sockaddr_storage	ss;
	int			r;
#ifndef _WIN32
	unsigned int		sslen = sizeof ss;
#else
	int			sslen = sizeof ss;
#endif

	assert(conn_is_valid(conn));

	memzero(hostname, hlen);
	*proto = 0;
	*port = 0;

	memzero(&ss, sizeof ss);
	if (local)
		r = getsockname(conn->sock, (struct sockaddr *)&ss, &sslen);
	else
		r = getpeername(conn->sock, (struct sockaddr *)&ss, &sslen);
	if (r != 0) {
		logline(log_WARNING_, CONN_ID " could not get%sname",
			conn_id(conn), local ? "sock" : "peer");
		return (false);
	}

	switch (ss.ss_family) {
	case AF_INET:
		inet_ntop(ss.ss_family,
			  &((struct sockaddr_in *)&ss)->sin_addr,
			  hostname, hlen);
		*port = ntohs(((struct sockaddr_in *)&ss)->sin_port);
		break;

	case AF_INET6:
		inet_ntop(ss.ss_family,
			  &((struct sockaddr_in6 *)&ss)->sin6_addr,
			  hostname, hlen);
		*port = ntohs(((struct sockaddr_in6 *)&ss)->sin6_port);
		break;

	default:
		logline(log_CRIT_, CONN_ID " Unsupported AF %u",
			conn_id(conn), ss.ss_family);
		return (false);
		break;
	}

	/* The protocol */
	*proto = conn->protocol;

	return (true);
}

#ifdef CONN_SSL
bool
conn_ssl_start(conn_t *conn, SSL_CTX *ssl_ctx, const char *ssl_psk_key,
	       const char *ssl_psk_id, bool serverside)
{
	int rc;

	/* Set up parameters */
	conn->ssl_psk_key = ssl_psk_key;
	conn->ssl_psk_id = ssl_psk_id;

	conn->ssl = SSL_new(ssl_ctx);
	if (!conn->ssl) {
		logline(log_ERR_, CONN_ID " SSL_new() failed", conn_id(conn));
		return (false);
	}

	/* We want to find ourselves again */
	SSL_set_app_data(conn->ssl, conn);

	conn->ssl_bio_in = BIO_new(BIO_s_mem());
	if (!conn->ssl_bio_in) {
		logline(log_ERR_, CONN_ID " BIO_new(in) failed", conn_id(conn));
		return (false);
	}
	BIO_set_nbio(conn->ssl_bio_in, 1);
	BIO_set_callback(conn->ssl_bio_in, conn_ssl_bio_cb);
	BIO_set_callback_arg(conn->ssl_bio_in, (char *)conn);

	conn->ssl_bio_out = BIO_new(BIO_s_mem());
	if (!conn->ssl_bio_out) {
		logline(log_ERR_, CONN_ID " BIO_new(out) failed", conn_id(conn));
		return (false);
	}
	BIO_set_nbio(conn->ssl_bio_out, 1);
	BIO_set_callback(conn->ssl_bio_out, conn_ssl_bio_cb);
	BIO_set_callback_arg(conn->ssl_bio_out, (char *)conn);

	/* Set the input/output handler */
	SSL_set_bio(conn->ssl, conn->ssl_bio_in, conn->ssl_bio_out);

	if (serverside) {
		/* This socket was accepted */
		SSL_set_accept_state(conn->ssl);
	} else {
		bool done = false;
		int se;
		unsigned int loops = 0;

		logline(log_DEBUG_, CONN_ID " Attempting SSL Client Handshake",
			conn_id(conn));

		/* Do handshaky stuff */
		SSL_set_connect_state(conn->ssl);

		/* Arbitrary limit of 42 so we do not loop forever */
		for (loops = 0; loops < 42 && !done; loops++) {
			logline(log_DEBUG_,
				CONN_ID " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
				conn_id(conn));
			rc = SSL_connect(conn->ssl);

			done = (rc == 1) && SSL_is_init_finished(conn->ssl);

			if (!done) {
				se  = SSL_get_error(conn->ssl, rc);

				switch (se) {
				case SSL_ERROR_NONE:
					logline(log_WARNING_,
						CONN_ID " ERR: NONE",
						conn_id(conn));
					return (false);

				case SSL_ERROR_WANT_READ:
					logline(log_WARNING_,
						CONN_ID " Want Read",
						conn_id(conn));
					conn_recvA(conn);
					break;

				case SSL_ERROR_WANT_WRITE:
					logline(log_WARNING_,
						CONN_ID " Want Write",
						conn_id(conn));
					conn_flush(conn);
					break;

				case SSL_ERROR_ZERO_RETURN:
				case SSL_ERROR_SSL:
				default:
					conn_ssl_err(conn, "SSL_connect");
					return (false);
				}
			} /* !done */
		} /* loop */

		if (!done) {
			logline(log_WARNING_,
				CONN_ID " SSL Client Handshake Failure",
				conn_id(conn));
			return (false);
		}

		/* All okay */
		logline(log_DEBUG_,
			CONN_ID " SSL Client Handshake OK", conn_id(conn));
	}

	return (true);
}

#endif /* CONN_SSL */
