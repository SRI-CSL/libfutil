#include <libfutil/conn.h>

/* XXX: conn_id + connset_id are not mutex'ed thus could race in theory */
/* XXX: WIN32 support needs to be re-added as pipe() is not there */

/*
 * Debug polling mechanism - enables extra checks and fassert()s
*/
/* #define POLLDEBUG */

/*
 * For the keyfile.pem + server.pem use:
 *
 *	openssl req -newkey rsa:1024 -x509 -nodes -keyout keyfile.pem \
 *	 	    -new -out server.pem
 */

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

static void
connset_lock(connset_t *cs);
static void
connset_lock(connset_t *cs) {
	mutex_lock(cs->mutex);
}

static void
connset_unlock(connset_t *cs);
static void
connset_unlock(connset_t *cs) {
	mutex_unlock(cs->mutex);
}

#ifdef DEBUG
static const char *
connset_list(connset_t *cs, hlist_t *l);
static const char *
connset_list(connset_t *cs, hlist_t *l) {
	return	(l == &cs->ready	? "ready" :
		(l == &cs->active	? "active" :
		(l == &cs->inactive	? "inactive" :
		(l == &cs->handling	? "handling" :
		(l == NULL		? "<none>" :
					  "<unknown>")))));
}
#endif

void
connset_trigger_clear(connset_t *cs, fd_set *fd_r);
void
connset_trigger_clear(connset_t *cs, fd_set *fd_r) {
	char buf;

	/* Reset the trigger count */
	if (cs->triggers == 0) {
		return;
	}

	/* No need to read when the bit is not set */
	if (!FD_ISSET(cs->pipe[0], fd_r)) {
		return;
	}

	/* Reset the count */
	cs->triggers = 0;

	/* Receive the triggers */
	while (read(cs->pipe[0], &buf, 1) == 1);
}

/* Locked by caller */
void
connset_trigger_set(connset_t *cs);
void
connset_trigger_set(connset_t *cs) {
	/*
	 * Only trigger when it was not triggered yet
	 * this avoids unnessecary pipe interaction
	 */
	if (cs->triggers == 0) {
		/* Trigger it one more time */
		cs->triggers++;
		write(cs->pipe[1], "F", 1);
	}
}

/* Locked by caller */
bool
connset_init(connset_t *cs) {
	/* Unique connection number, for easy debugging */
	static unsigned int	connset_id = 0;

	/* A new one */
	memzero(cs, sizeof *cs);
	cs->id = ++connset_id;

	/* Try creating the pipe first */
	cs->pipe[0] = cs->pipe[1] = -1;
	if (pipe(cs->pipe) == -1) {
		return (false);
		
	}

	/* The pipes should be non-blocking */
	if (fcntl(cs->pipe[0], F_SETFL, O_NONBLOCK) == -1) {
		log_err("fcntl(pipe) failed");
		return (false);
	}

	/* Initialize the rest */
	mutex_init(cs->mutex);
	list_init(&cs->active);
	list_init(&cs->ready);
	list_init(&cs->inactive);
	list_init(&cs->handling);

	log_dbg(
		"active: " LIST_ID
		", ready: " LIST_ID
		", inactive: " LIST_ID
		", handling: " LIST_ID,
		list_id(&cs->active),
		list_id(&cs->ready),
		list_id(&cs->inactive),
		list_id(&cs->handling)
		);

	FD_ZERO(&cs->fd_read);
	FD_ZERO(&cs->fd_write);

	/* We are interrested in reading as then something triggered it */
	FD_SET(cs->pipe[0], &cs->fd_read);

	/* Negative is the maximum */
	cs->hifd = -1;

	return (true);
}

#ifdef DEBUG
static unsigned int
connset_destroy_list(hlist_t *l, const char *state);
static unsigned int
connset_destroy_list(hlist_t *l, const char *state) {
#else
static unsigned int
connset_destroy_list(hlist_t *l, const char UNUSED *state);
static unsigned int
connset_destroy_list(hlist_t *l, const char UNUSED *state) {
#endif
	unsigned int	i = 0;
	conn_t		*conn;

	while ((conn = (conn_t *)list_pop(l))) {
		conn->connset = NULL;
		conn->connset_l = NULL;

		i++;
		log_dbg(
			"closing %s " CONN_ID,
			state, conn_id(conn));
		conn_destroy(conn);
		mfree(conn, sizeof *conn, "conn");
	}

	return (i);
}

void
connset_destroy(connset_t *cs) {
	unsigned int	i;

	do {
		i  = connset_destroy_list(&cs->handling,"handling");
		i += connset_destroy_list(&cs->active,	"active");
		i += connset_destroy_list(&cs->ready,	"ready");
		i += connset_destroy_list(&cs->inactive,"inactive");
	} while (i > 0);

	/* Should always be empty */
	fassert(connset_is_empty(cs));

	/* Close the pipes */
	for (i=0; i < lengthof(cs->pipe); i++) {
		if (cs->pipe[i] != -1) {
			close(cs->pipe[i]);
			cs->pipe[i] = -1;
		}
	}

	/* Destroy lists */
	list_destroy(&cs->ready);
	list_destroy(&cs->active);
	list_destroy(&cs->inactive);
	mutex_destroy(cs->mutex);
}

#ifdef POLLDEBUG
static void
connset_poll_list(const char *type, hlist_t *l, fd_set *fd_r, fd_set *fd_w);
static void
connset_poll_list(const char *type, hlist_t *l, fd_set *fd_r, fd_set *fd_w) {
	conn_t		*conn, *conn_next;
	
	list_lock(l);
	list_for(l, conn, conn_next, conn_t *) {
		log_dbg(
			"  %s: " CONN_ID " " SOCK_ID
			", (i:%s/%s o:%s/%s)",
			type,
			conn_id(conn),
			conn_sock(conn),
			yesno(conn_wnt_in(conn)),
			yesno(FD_ISSET(conn->sock, fd_r)),
			yesno(conn_wnt_out(conn)),
			yesno(FD_ISSET(conn->sock, fd_w)));
	}
	list_unlock(l);
}
#endif

int
connset_poll(connset_t *cs) {
	struct timeval	timeout;
	conn_t		*conn, *conn_next;
	fd_set		fd_r, fd_w;
	int		i, errsv, hifd;
#ifdef POLLDEBUG
	int		j;
	uint64_t	a_s, a_ms, b_s, b_ms, d;
#endif

	while (true) {
		/* log_dbg("..."); */
		connset_lock(cs);

		/* What we want to check */
		hifd = cs->hifd + 1;
		memcpy(&fd_r, &cs->fd_read, sizeof fd_r);
		memcpy(&fd_w, &cs->fd_write, sizeof fd_w);

#ifdef POLLDEBUG
		log_dbg("Pre-select:");

		for (i = 0; i < hifd; i++) {
			if (FD_ISSET(i, &fd_r))
				log_dbg("   read: " SOCK_ID, i);
			if (FD_ISSET(i, &fd_w))
				log_dbg("   write: " SOCK_ID, i);
		}

		connset_poll_list("act", &cs->active,	&fd_r, &fd_w);
		connset_poll_list("rdy", &cs->ready,	&fd_r, &fd_w);
		connset_poll_list("ina", &cs->inactive, &fd_r, &fd_w);
		connset_poll_list("hdl", &cs->handling, &fd_r, &fd_w);
#endif
		connset_unlock(cs);

		/*
		 * Timeout every second, we get triggered
		 * when we need to be quicker
		 */
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		thread_setstate(thread_state_select);
		errno = 0;

#ifdef POLLDEBUG
		a_s = gettimes(&a_ms);
#endif
		i = select(hifd, &fd_r, &fd_w, NULL, &timeout);
 		errsv = errno;

#ifdef POLLDEBUG
		b_s = gettimes(&b_ms);

		if (a_ms > b_ms)
		{
			b_s--;
			d = a_ms - b_ms;
		}
		else
		{
			d = b_ms - a_ms;
		}

		connset_lock(cs);
		log_dbg("select() = %u (sec = %" PRIu64 ".%03" PRIu64 ", triggers = %" PRIu64 ")", i, b_s - a_s, d, cs->triggers);
		connset_unlock(cs);
#endif
		thread_setstate(thread_state_running);

		if (i < 0) {
			/* Ignore signals */
			if (errsv == EINTR) {
				log_ntc("Select Interrupted");
			} else if (errsv == EBADF) {
				/*
				 * As we are multi-threaded a
				 * socket might disappear while we are
				 * checking it
				 */
				log_ntc("Bad Filedescriptor");
				continue;
			} else {
				log_err("Select Failed");
			}

			return (-1);
		}

		/* Timeout or needing to stop running? */
		if (i == 0 || !thread_keep_running()) {
			/* log_dbg("Timeout"); */
			break;
		}

		/* Lock the connset first */
		connset_lock(cs);

		/* Clear outstanding events */
		connset_trigger_clear(cs, &fd_r);

		/* Check clients and move them from active to ready */
		list_lock(&cs->active);
		list_for(&cs->active, conn, conn_next, conn_t *) {
			/* Sanity check */
			fassert(cs == conn->connset);

			log_dbg(
				CONN_ID " checking " SOCK_ID
				", (i:%s/%s o:%s/%s)",
				conn_id(conn),
				conn_sock(conn),
				yesno(conn_wnt_in(conn)),
				yesno(FD_ISSET(conn->sock, &fd_r)),
				yesno(conn_wnt_out(conn)),
				yesno(FD_ISSET(conn->sock, &fd_w)));

			/* No events found for this one yet */
			conn->hasevents = 0;

			if (FD_ISSET(conn->sock, &fd_r)) {
				if (conn_wnt_in(conn)) {
					conn->hasevents |= CONN_POLLIN;
#ifdef POLLDEBUG
					j++;
#endif
				} else {
					log_dbg(
						CONN_ID " have IN signal, "
						"but did not want",
						conn_id(conn));
#ifdef POLLDEBUG
					fassert(false);
#endif
				}
			}

			if (FD_ISSET(conn->sock, &fd_w)) {
				if (conn_wnt_out(conn)) {
					conn->hasevents |= CONN_POLLOUT;
#ifdef POLLDEBUG
					j++;
#endif
				} else {
					log_dbg(
						CONN_ID " have OUT signal, "
						"but did not want",
						conn_id(conn));
#ifdef POLLDEBUG
					fassert(false);
#endif
				}
			}

			if (conn->hasevents != 0) {
				log_dbg(
					CONN_ID " Adding to ready list",
					conn_id(conn));

				/*
				 * Move it to the ready list
				 * (active is locked)
				 *
				 * Clear the bits so that select() does
				 * not notice them
				 */
				FD_CLR(conn->sock, &conn->connset->fd_read);
				FD_CLR(conn->sock, &conn->connset->fd_write);

				fassert(conn->connset_l == &conn->connset->active);
				list_remove(&conn->connset->active,
					    &conn->node);

				conn->connset_l = &conn->connset->ready;
				list_addtail_l(&conn->connset->ready,
					       &conn->node);

				log_dbg(
					CONN_ID " Added to list: ready",
					conn_id(conn));
			}
		}

		list_unlock(&cs->active);

		connset_unlock(cs);
	}

	return (0);
}

static void
conn_lock(conn_t *conn);
static void
conn_lock(conn_t *conn) {
	mutex_lock(conn->mutex);
}

static void
conn_unlock(conn_t *conn);
static void
conn_unlock(conn_t *conn) {
	mutex_unlock(conn->mutex);
}

#define conn_bits(func,x)			\
bool						\
func(conn_t *conn) {				\
	bool b;					\
						\
/*	conn_lock(conn);	*/		\
	b = (x);				\
/*	conn_unlock(conn);	*/		\
						\
	return (b);				\
}

conn_bits(conn_wnt_in,	conn->wntevents & CONN_POLLIN)
conn_bits(conn_wnt_out,	conn->wntevents & CONN_POLLOUT)
conn_bits(conn_poll_in,	(conn->hasevents & CONN_POLLIN) &&
	   		(conn->wntevents & CONN_POLLIN))
conn_bits(conn_poll_out,(conn->hasevents & CONN_POLLOUT) &&
			(conn->wntevents & CONN_POLLOUT))

static void
conn_set_nonblocking(conn_t *conn);
static void
conn_set_nonblocking(conn_t *conn) {
#ifndef _WIN32
	int flags;
#else
	u_long flags;
#endif

	fassert(conn_is_valid(conn));

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
conn_set_blocking(conn_t *conn);
static void
conn_set_blocking(conn_t *conn) {
#ifndef _WIN32
	int flags;
#else
	u_long flags;
#endif

	fassert(conn_is_valid(conn));

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
	fassert(conn);

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

	log_wrn(CONN_ID " SSL Error: %s :: %s (%u / %s)",
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

	log_dbg(CONN_ID "", conn_id(conn));

	/* Required to be there */
	fassert(conn->ssl_psk_id != NULL);
	fassert(conn->ssl_psk_key != NULL);

	if (!identity) {
		log_ntc(CONN_ID " client did not send PSK identity",
			conn_id(conn));
		return (0);
	}

	log_dbg(
		CONN_ID " identity_len: %u, identity: %s",
		conn_id(conn),
		(unsigned int)strlen(identity), identity);

	/* Is it the identity we expect? */
	if (strcmp(identity, conn->ssl_psk_id) != 0)
	{
		log_ntc(
		 	CONN_ID " PSK error: client identity not found"
			" (got '%s' expected '%s')n",
			conn_id(conn), identity, conn->ssl_psk_id);
		return (0);
	}

	log_dbg(CONN_ID " PSK client identity found", conn_id(conn));

	/* convert the PSK key to binary */
	ret = BN_hex2bn(&bn, conn->ssl_psk_key);
	if (!ret)
	{
		log_ntc(
			CONN_ID " Could not convert PSK key '%s' to BIGNUM",
			conn_id(conn), conn->ssl_psk_key);
		if (bn) {
			BN_free(bn);
		}
		return (0);
	}

	if (BN_num_bytes(bn) > (int)max_psk_len)
	{
		log_ntc(
			CONN_ID " psk buffer of callback is too small (%u) "
			"for key (%u)",
			conn_id(conn), max_psk_len, BN_num_bytes(bn));
		BN_free(bn);
		return (0);
	}

	ret = BN_bn2bin(bn, psk);
	BN_free(bn);

	if (ret < 0) {
		log_ntc(
			CONN_ID " bn2bin failed for PSK",
			conn_id(conn));
		return(0);
	}

	psk_len = (unsigned int)ret;

	log_dbg(
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

	log_dbg(CONN_ID "", conn_id(conn));
	if (!hint) {
		log_dbg(
			CONN_ID " NULL PSK identity hint", conn_id(conn));
	} else {
		log_dbg(CONN_ID " PSK identity hint \"%s\"",
			conn_id(conn), hint);
	}

	/*
	 * lookup PSK identity and PSK key based on the given
	 * identity hint here
	 */
	n = snprintf(identity, max_identity_len, "%s", conn->ssl_psk_id);
	if (!snprintfok(n, max_identity_len)) {
		log_err(
			CONN_ID " Could not store identity",
			conn_id(conn));
		return (0);
	}

	log_dbg(
		CONN_ID " identity: \"%s\" (%u)",
		conn_id(conn), identity, n);

	n = BN_hex2bn(&bn, conn->ssl_psk_key);
	if (!n)
	{
		log_err(
			CONN_ID " Could not convert PSK key '%s' to BIGNUM",
			conn_id(conn), conn->ssl_psk_key);
		if (bn)
			BN_free(bn);
		return (0);
	}

	if ((unsigned int)BN_num_bytes(bn) > max_psk_len)
	{
		log_err(CONN_ID " psk buffer of callback is too "
			" small (%u) for key (%d)",
			conn_id(conn), max_psk_len, BN_num_bytes(bn));
		BN_free(bn);
		return (0);
	}

	psk_len = BN_bn2bin(bn, psk);
	BN_free(bn);

	if (psk_len == 0) {
		log_err(CONN_ID " psk_len = %u", conn_id(conn), psk_len);
		return (0);
	}

	log_dbg(CONN_ID " Created PSK len = %u", conn_id(conn), psk_len);
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
		log_dbg(
			CONN_ID " %s:%s (%d)",
			conn_id(conn), str, SSL_state_string_long(ssl), ret);
	} else if (where & SSL_CB_ALERT) {
		log_dbg(
			CONN_ID " SSL3 alert %s:%s:%s (%d)",
			conn_id(conn),
			(where & SSL_CB_READ) ? "read" : "write",
			SSL_alert_type_string_long(ret),
			SSL_alert_desc_string_long(ret), ret);
	}
	else if (where & SSL_CB_EXIT) {
		if (ret == 0) {
			log_dbg(
				CONN_ID " %s:failed in %s (%d)",
				conn_id(conn), str,
				SSL_state_string_long(ssl), ret);
		} else if (ret < 0) {
			log_dbg(
				CONN_ID " %s:error in %s (%d)",
				conn_id(conn), str,
				SSL_state_string_long(ssl), ret);
		}
	} else {
		log_dbg(
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

	log_dbg(CONN_ID " %s %s%s [length %04lx]%s%s\n",
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
	log_dbg("...");

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

	log_dbg("...");

	if (!initialized) {
		log_dbg("Initializing SSL");
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
#ifdef DEBUG
	static const char *states[] = {
				"UNUSED", "LISTENING", "ACCEPTING",
				"CONNECTING", "CONNECTED" };
	const char	*st;

	st = state < lengthof(states) ? states[state] : "?UNKNOWN!";

	log_dbg(CONN_ID " is now %s", conn_id(conn), st);
#endif

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
			log_crt(
				"Winsock error - Initialization failed");
			WSACleanup();
			return (false);
		}
	}
#else
        /* Ignore SIGPIPE for when we read/write and the connection breaks */
        signal(SIGPIPE, SIG_IGN);
#endif

	fassert(conn != NULL);

	/* Empty it out */
	memzero(conn, sizeof *conn);

	/* Give it a number we can remember */
	conn->id = ++conn_id;
	log_dbg(CONN_ID, conn_id(conn));

	node_init(&conn->node);
	mutex_init(conn->mutex);

	/* Initial assignment */
	conn->sock = INVALID_SOCKET;
	conn->connset = NULL;
	conn->clientdata = clientdata;
	conn_set_state(conn, CONN_UNUSED);

	conn->sendfile_fd = -1;
	conn->sendfile_off = 0;
	conn->sendfile_len = 0;

	/* Init the buffers */
	if (	!buf_init(&conn->recv) ||
		!buf_init(&conn->send) ||
		!buf_init(&conn->send_headers)) {
		return (false);
	}

	/* 2 MiB incoming */
	if (!buf_minsize(&conn->recv, 2 * 1024 * 1024)) {
		return (false);
	}

	return (true);
}

/* What do we want to hear? (Mutex locked by caller) */
static void
conn_eventsA(conn_t *conn, uint16_t events);
static void
conn_eventsA(conn_t *conn, uint16_t events) {
	hlist_t *new_l;
	bool	changed;

	fassert(conn_is_valid(conn));

	/* Nothing to do? */
        if (conn->wntevents == events)
		return;

	/*
	 * We allow sockets to work without a connset
	 * they are synchronous then though
	 */
	if (conn->connset == NULL) {
		conn->wntevents = events;

		log_dbg(CONN_ID " no connset, events set to: %s %s",
			conn_id(conn),
			conn_wnt_in(conn)	? "IN" : ".",
			conn_wnt_out(conn)	? "OUT" : ".");
		return;
	}

	/* Lock her up */
	connset_lock(conn->connset);

	/* When handling, don't change anything except what we want (after if) */
	if (conn->connset_l == &conn->connset->handling) {
		log_dbg(
			CONN_ID " handling thus not changing lists",
			conn_id(conn));
	} else {
		log_dbg(
			CONN_ID " want=%u, events=%u",
			conn_id(conn), conn->wntevents, events);

		/* Currently monitoring for something? */
		if ((conn->wntevents & CONN_POLLIN) !=
		          (events & CONN_POLLIN)) {

			if (events & CONN_POLLIN)
				FD_SET(conn->sock, &conn->connset->fd_read);
			else
				FD_CLR(conn->sock, &conn->connset->fd_read);

			changed = true;
		}

		if ((conn->wntevents & CONN_POLLOUT) !=
		          (events & CONN_POLLOUT)) {

			if (events & CONN_POLLOUT)
				FD_SET(conn->sock, &conn->connset->fd_write);
			else
				FD_CLR(conn->sock, &conn->connset->fd_write);

			changed = true;
		}

		if (changed) {
			/*
			 * Trigger the change
			 * this 'aborts' the select()
			 * that it is likely in directly
			 */
			connset_trigger_set(conn->connset);
		}

		log_dbg(
			CONN_ID " currently on list: %s",
			conn_id(conn),
			connset_list(conn->connset, conn->connset_l));

		/* Stay on ready when already there, go active, or go inactive otherwise */
		new_l = events != CONN_POLLNONE ?
				(conn->connset_l == &conn->connset->ready ?
				  &conn->connset->ready : &conn->connset->active) :
				&conn->connset->inactive;

		log_dbg(
			CONN_ID " new list: %s",
			conn_id(conn),
			connset_list(conn->connset, new_l));

		/* Different list? */
		if (conn->connset_l != new_l) {

			/* Remove it from the current list */
			if (conn->connset_l != NULL) {
				list_remove_l(conn->connset_l, &conn->node);
			}

			/* The current list */
			conn->connset_l = new_l;

			/* Add it to active or inactive */
			list_addtail_l(new_l, &conn->node);
		}

		log_dbg(
			CONN_ID " (non-handling portion done)",
			conn_id(conn));
	}

	/* They match now */
	conn->wntevents = events;

	log_dbg(CONN_ID " events are now: %s %s, list: %s",
		conn_id(conn),
		conn_wnt_in(conn)	? "IN" : ".",
		conn_wnt_out(conn)	? "OUT" : ".",
		connset_list(conn->connset, conn->connset_l));

	/* Ensure that we track the hi_fd properly */
	if (events != 0) {
/* Windows does not use the highest fd param, it is there for compat only */
#ifndef _WIN32
		/* Make sure we have the right Highest FD */
		if (conn->sock > conn->connset->hifd) {
			log_dbg(
				CONNS_ID " New high FD: " SOCK_ID " " CONN_ID,
				conn->connset->id,
				conn_sock(conn),
				conn_id(conn));
			conn->connset->hifd = conn->sock;
		} else {
			log_dbg(
				CONNS_ID " Old high FD: " SOCK_ID
				", " CONN_ID " = " SOCK_ID,
				conn->connset->id,
				conn->connset->hifd,
				conn_id(conn),
				conn_sock(conn));
		}
#endif
	}

	/* Release her */
	connset_unlock(conn->connset);
}

void
conn_events(conn_t *conn, uint16_t events) {
	conn_lock(conn);
	conn_eventsA(conn, events);
	conn_unlock(conn);
}

/* Locked by caller */
static void
conn_set_connset(conn_t *conn, connset_t *cs);
static void
conn_set_connset(conn_t *conn, connset_t *cs) {
	uint16_t events = conn->wntevents;

	log_dbg(CONN_ID " has%s current",
		conn_id(conn),
		conn->connset == NULL ? " no" : "");

	/*
	 * With a connset it is a non-blocking socket
	 * Without a connset it is a blocking socket
	 */

	/* Nothing to do if it is the same connset */
	if (conn->connset == cs) {
		if (cs != NULL) {
			log_dbg(CONN_ID " same connset " CONNS_ID,
				conn_id(conn), conn->connset->id);
		} else {
			log_dbg(CONN_ID " no connset",
				conn_id(conn));
		}
		return;
	}

	/* Remove from old connset */
	if (conn->connset != NULL) {
		log_dbg(CONN_ID " old connset " CONNS_ID,
			conn_id(conn), conn->connset->id);
		conn_eventsA(conn, 0);
	}

	/* Add to new connset */
	if (cs != NULL) {
		log_dbg(CONN_ID " new connset " CONNS_ID,
			conn_id(conn), cs->id);
		conn_eventsA(conn, events);
	}

	conn->connset = cs;
}

/* Destroy the connection, final cleanup */
void
conn_destroy(conn_t *conn) {
	log_dbg(CONN_ID, conn_id(conn));

	/* Close the socket first if needed */
	conn_close(conn);

	log_dbg(CONN_ID " destroying buffers", conn_id(conn));

	buf_destroy(&conn->recv);
	buf_destroy(&conn->send);
	buf_destroy(&conn->send_headers);

	/* Unlink the node from any list it was put on */
	if (conn->connset != NULL) {
		/* XXX: should be 'inactive' as that is what conn_close() causes */
		list_remove_l(conn->connset_l, &conn->node);

		/* No more connset here */
		conn->connset = NULL;
		conn->connset_l = NULL;
	}

	mutex_destroy(conn->mutex);
	node_destroy(&conn->node);

	log_dbg(CONN_ID " gone", conn_id(conn));

	/* Clean her out */
	memzero(conn, sizeof *conn);
}

void
conn_set_posthandle(conn_t *conn, conn_posthandle_f f, void *user) {
	/* should not be set multiple times */
	fassert(conn->posthandle_f == NULL);

	/* The function and user data */
	conn->posthandle_f = f;
	conn->posthandle_u = user;
}

/*
 * For conn_get_ready() and conn_get_one_ready() and suggested
 * around conn_accept()
 *
 * This avoids conn_eventsA() list swapping when the list is handling thus
 * avoids connections to go onto the active list and thus being picked up
 * by another thread.
 *
 * Finalize this with connset_handling_done()
 *
 * This puts a connection on the handling list.
 */
static void
connset_handling_setupL(conn_t *conn);
static void
connset_handling_setupL(conn_t *conn) {
	log_dbg(CONN_ID, conn_id(conn));

	/* Clear the bits so that select() ignores them */
	if (conn->wntevents & CONN_POLLIN) {
		FD_CLR(conn->sock, &conn->connset->fd_read);
	}

	if (conn->wntevents & CONN_POLLOUT) {
		FD_CLR(conn->sock, &conn->connset->fd_write);
	}

	/*
	 * We took conn from a list add it to handling list
	 */
	fassert(conn->connset_l == &conn->connset->ready);
	conn->connset_l = &conn->connset->handling;
	list_addtail_l(&conn->connset->handling, &conn->node);

	log_dbg(
		CONN_ID " done, list: handling",
		conn_id(conn));
}

static void
connset_handling_setupA(conn_t *conn);
static void
connset_handling_setupA(conn_t *conn) {
	/* Lock her up */
	conn_lock(conn);
	connset_lock(conn->connset);

	/* Locked, make magic happen */
	connset_handling_setupL(conn);

	/* Release her */
	connset_unlock(conn->connset);
	conn_unlock(conn);
}

void
connset_handling_setup(conn_t *conn) {
	log_dbg(CONN_ID, conn_id(conn));

	/* Lock her up */
	conn_lock(conn);
	connset_lock(conn->connset);

	log_dbg(
		CONN_ID " list: %s",
		conn_id(conn),
		connset_list(conn->connset, conn->connset_l));

	/* Should not be on ready or handling lists */
	fassert(conn->connset_l != &conn->connset->ready);
	fassert(conn->connset_l != &conn->connset->handling);
	list_remove_l(conn->connset_l, &conn->node);

	/* Fake that it was on the ready list */
	conn->connset_l = &conn->connset->ready;

	connset_handling_setupL(conn);

	/* Release her */
	connset_unlock(conn->connset);
	conn_unlock(conn);
}

conn_t *
connset_get_ready(connset_t *cs) {
	conn_t *conn;

	conn = (conn_t *)list_getnext(&cs->ready);
	if (conn != NULL) {
		connset_handling_setupA(conn);
	}

	return (conn);
}

conn_t *
connset_get_one_ready(connset_t *cs) {
	conn_t *conn;

	conn = (conn_t *)list_pop(&cs->ready);
	if (conn != NULL) {
		connset_handling_setupA(conn);
	}

	return (conn);
}

/* Paired with a connset_get_{one_}ready and thus connset_handling_setup() */
void
connset_handling_done(conn_t *conn, bool keeplocked) {
	hlist_t	*l;
	bool	changed = false;

	/* Has to be one some list */
	fassert(conn->connset_l != NULL);

	log_dbg(CONN_ID " (kh=%s)", conn_id(conn), yesno(keeplocked));

	/* Lock it */
	conn_lock(conn);
	connset_lock(conn->connset);

	log_dbg(
		CONN_ID " list: %s",
		conn_id(conn),
		connset_list(conn->connset, conn->connset_l));

	/* Should still be on the handling list */
	fassert(conn->connset_l == &conn->connset->handling);

	if (!keeplocked) {
		/* Set the bits correctly so that select() answers again */
		if (conn->wntevents & CONN_POLLIN) {
			FD_SET(conn->sock, &conn->connset->fd_read);
			changed = true;
		}

		if (conn->wntevents & CONN_POLLOUT) {
			FD_SET(conn->sock, &conn->connset->fd_write);
			changed = true;
		}

		/* Place it back on the active/inactive list */
		if (conn->wntevents == CONN_POLLNONE) {
			l = &conn->connset->inactive;
		} else {
			l = &conn->connset->active;
		}

		/* Put it on the right list */
		list_remove_l(conn->connset_l, &conn->node);
		conn->connset_l = l;
		list_addtail_l(l, &conn->node);

		log_dbg(
				CONN_ID " new list: %s",
				conn_id(conn),
				connset_list(conn->connset, conn->connset_l));
	} else {
		log_dbg(
				CONN_ID " sticking to list: %s",
				conn_id(conn),
				connset_list(conn->connset, conn->connset_l));
	}

	if (conn->posthandle_f) {
		conn->posthandle_f(conn, conn->posthandle_u);
		conn->posthandle_f = NULL;
		conn->posthandle_u = NULL;
	}

	/* Trigger as select() needs to know about our changes */
	if (changed) {
		connset_trigger_set(conn->connset);
	}

	/* Release it */
	connset_unlock(conn->connset);
	conn_unlock(conn);
}

/* Close the connection but still available for re-use */
void
conn_close(conn_t *conn) {
	conn_lock(conn);

	/* Already closed? */
	if (conn->sock == INVALID_SOCKET) {
		log_dbg(CONN_ID " Already closed", conn_id(conn));
		conn_unlock(conn);
		return;
	}

	log_dbg(
		CONN_ID " " SOCK_ID " closing",
		conn_id(conn), conn_sock(conn));

	/* Don't want to hear from this socket any further */
	conn_eventsA(conn, CONN_POLLNONE);

	/*
	 * Make the socket temporarily blocking
	 * This so we are sure that the shutdown()
	 * is totally completed
	 */
	conn_set_blocking(conn);

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
	buf_emptyL(&conn->recv);
	buf_emptyL(&conn->send);
	buf_emptyL(&conn->send_headers);

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
conn_is_eofA(conn_t UNUSED *conn);
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

	log_dbg(CONN_ID " checking for EOF", conn_id(conn));

	/* Async sockets will receive EOF at poll() time */
	if (conn->connset != NULL) {
		log_dbg(CONN_ID " checking for EOF (async)", conn_id(conn));
		return (false);
	}

	/* Peek if there is something */
	r = recv(conn->sock, buf, sizeof buf, MSG_PEEK | MSG_NOSIGNAL | MSG_DONTWAIT);

	/* Are we still connected? */
	ret = (r <= 0 && errno == ENOTCONN);

	log_dbg(CONN_ID " checking for EOF (%s)", conn_id(conn),yesno(ret));

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

#ifdef CONN_SSL
/* returns: true = done, false = not done */
/* Internal only, does not lock */
static bool
conn_ssl_flush(conn_t *conn);
static bool
conn_ssl_flush(conn_t *conn) {
	ssize_t r;

	fassert(conn_is_valid(conn));

	log_dbg(CONN_ID "", conn_id(conn));

	/* Nothing to do? */
	if (!conn->ssl || conn->ssl_out_len == 0) {
		log_dbg(CONN_ID " nothing to do", conn_id(conn));
		return (true);
	}

	/* Send the crypted bits over the wire */
	r = send(conn->sock, conn->ssl_out, conn->ssl_out_len, MSG_NOSIGNAL);
	if (r <= -1) {
		log_ntc(CONN_ID " ERR %" PRId64 " (SSL)",
			conn_id(conn), r);
		return (false);
	}

	if (((uint64_t)r) != conn->ssl_out_len) {
		/*
		 * Didn't write it all yet, thus shove it up
		 * and try again in the next round
		 */
		uint64_t left;

		fassert(r < conn->ssl_out_len);
		left = conn->ssl_out_len - r;

		log_dbg(
			CONN_ID " sent %" PRIu64 ", but %" PRIu64 " left",
			conn_id(conn), r, left);

		memmove(&conn->ssl_out, &conn->ssl_out[r], left);

		conn->ssl_out_len = left;

		/* Our work is done for now, try again later */
		return (false);
	}

	/* Done writing all our SSL data */
	conn->ssl_out_len = 0;
	log_dbg(CONN_ID " done %" PRIu64, conn_id(conn), r);

	return (true);
}

static void
conn_ssl_bio_write(conn_t *conn);
static void
conn_ssl_bio_write(conn_t *conn) {
	int rc;

	log_dbg(CONN_ID " in: %u", conn_id(conn), conn->ssl_in_len);

	/*
	 * socket -> ssl_in[c] - BIO_write -> SSL_read -> data[p];
	 *
	 * We read from the socket crypted data into ssl_in,
	 * thus write towards OpenSSL which can then decrypt it
	 */
	rc = BIO_write(conn->ssl_bio_in, &conn->ssl_in, conn->ssl_in_len);
	log_dbg(CONN_ID " BIO_write = %d", conn_id(conn), rc);

	/*
	 * The return code includes the amount of data written by OpenSSL
	 * Which is also why we attempt to write 0 data streams as OpenSSL
	 * adds extra bytes for the crypto.
	 */
	if (rc <= 0) {
		/* Nothing done */
		return;
	}

	log_dbg(
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
			log_dbg("Attempting SSL Handshake");
			rc = SSL_do_handshake(conn->ssl);
		}
	} else {
		log_dbg("Attempting SSL Read");
		buf_lock(&conn->recv);
		rc = SSL_read(conn->ssl, buf_bufend(&conn->recv),
			      conn_buffer_left(conn));

		if (rc > 0) {
			buf_added(&conn->recv, rc);

			log_dbg(
				CONN_ID " got additional %u, "
				"total = %" PRIu64,
				conn_id(conn), rc, buf_cur(&conn->recv));
		}
		buf_unlock(&conn->recv);
	}

	if (rc <= 0) {
		conn_ssl_err(conn, "SSL_read error");
	}
}

static void
conn_ssl_bio_read(conn_t *conn);
static void
conn_ssl_bio_read(conn_t *conn) {
	int rc;

	log_dbg(CONN_ID "", conn_id(conn));

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
	log_dbg(CONN_ID " BIO_read = %d", conn_id(conn), rc);
	if (rc > 0) {
		/* We got data that needs flushing */
		conn->ssl_out_len += rc;

		log_dbg(
			CONN_ID " BIO_read() = %u => %u",
			conn_id(conn), (unsigned int)rc, conn->ssl_out_len);

		conn_ssl_flush(conn);
	}
}

static void
conn_ssl_bio(conn_t *conn);
static void
conn_ssl_bio(conn_t *conn) {

	log_dbg(CONN_ID ", ...", conn_id(conn));

	conn_ssl_bio_write(conn);
	conn_ssl_bio_read(conn);

	buf_lock(&conn->recv);
	buf_lock(&conn->send);
	log_dbg(CONN_ID " in: %u/%u, out: %u/%u",
		conn_id(conn),
		conn->ssl_in_len, (unsigned int)buf_cur(&conn->recv),
		conn->ssl_out_len, (unsigned int)buf_cur(&conn->send));
	buf_unlock(&conn->send);
	buf_unlock(&conn->recv);
}

static long
conn_ssl_bio_cb(BIO *b, int oper, const char UNUSED *argp,
                        int UNUSED argi, long UNUSED argl, long retvalue);
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

	log_dbg(CONN_ID " oper = %u / %s ret: %ld, %s %s",
		conn_id(conn), oper, op, retvalue,
		(b == conn->ssl_bio_in  ? "IN"  : ".."),
		(b == conn->ssl_bio_out ? "OUT" : "..."));

	/* Flush our socket */
	conn_ssl_flush(conn);

	if (oper == BIO_CB_READ && b == conn->ssl_bio_in) {
		log_dbg(CONN_ID " Attempting BIO Write", conn_id(conn));
		conn_ssl_bio_write(conn);
	}

	if (	(oper == (BIO_CB_WRITE|BIO_CB_RETURN)) &&
		b == conn->ssl_bio_out) {

		/* Read a bit */
		log_dbg(CONN_ID " Attempting BIO Read", conn_id(conn));
		conn_ssl_bio_read(conn);
	}

	return (retvalue);
}
#endif /* CONN_SSL */

/* Locked by caller */
static int
conn_recvA(conn_t *conn);
static int
conn_recvA(conn_t *conn) {
	uint64_t	len;
	ssize_t		r;

	fassert(conn_is_valid(conn));
	log_dbg(CONN_ID " " SOCK_ID, conn_id(conn), conn_sock(conn));

	buf_lock(&conn->recv);

#ifdef CONN_SSL
	if (conn->ssl) {
		len = sizeof conn->ssl_in - conn->ssl_in_len;
		log_dbg(
			CONN_ID " ssl, cur = %" PRIu64 ", left = %" PRIu64,
			conn_id(conn), conn_buffer_cur(conn), len);
		thread_setstate(thread_state_io_read);
		r = recv(conn->sock, &conn->ssl_in[conn->ssl_in_len],
			 len, MSG_NOSIGNAL);
		thread_setstate(thread_state_running);
	} else {
#endif /* CONN_SSL */
		len = conn_buffer_left(conn);
		log_dbg(
			CONN_ID " cur = %" PRIu64 ", left = %" PRIu64,
			conn_id(conn), conn_buffer_cur(conn), len);
		thread_setstate(thread_state_io_read);
		r = recv(conn->sock, buf_bufend(&conn->recv),
			len, MSG_NOSIGNAL);
		thread_setstate(thread_state_running);
#ifdef CONN_SSL
	}
#endif

	/* Orderly shutdown? */
	if (r == 0) {
		log_dbg(
			CONN_ID " EOF (len=%" PRIsizet ")",
			conn_id(conn), r);
		/* Remote end closed socket */
		buf_unlock(&conn->recv);
		return (-ECONNRESET);
	}

	if (r < 0) {
		buf_unlock(&conn->recv);

		if (errno == EAGAIN) {
			log_dbg(
				CONN_ID " EAGAIN (len=%" PRIsizet ")",
				conn_id(conn), r);
			return (0);
		}

		log_dbg(
			CONN_ID " ERR (len=%" PRIsizet ")",
			conn_id(conn), r);
		return (-errno);
	}

	conn->last_recv = gettime();

#ifdef CONN_SSL
	if (conn->ssl) {
		log_dbg(CONN_ID " ssl received %" PRIu64, conn_id(conn), r);
		conn->ssl_in_len += r;

		conn_ssl_bio(conn);
	} else {
#endif
		uint64_t cur;

		cur = buf_cur(&conn->recv);

		buf_added(&conn->recv, r);

		log_dbg(
			CONN_ID " got additional %" PRIsizet ", "
			"total = %" PRIu64,
			conn_id(conn), r, buf_cur(&conn->recv));

		debugpacket((uint8_t *)&buf_buffer(&conn->recv)[cur], r);
#ifdef CONN_SSL
	}
#endif

	/* recv() doesn't return a null-terminated string, thus do it */
	*buf_bufend(&conn->recv) = '\0';

	/* Return the amount  bytes in the buffer */
	log_dbg(CONN_ID " return %" PRIu64,
		conn_id(conn), buf_cur(&conn->recv));

	len = buf_cur(&conn->recv);

	buf_unlock(&conn->recv);
	return (len);
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
	uint64_t	len;
	int		i;

	log_dbg(CONN_ID, conn_id(conn));

	conn_lock(conn);

	buf_lock(&conn->recv);

	/* Forever and ever */
	while (true) {

		/* Already something in our buffer? */
		if (buf_cur(&conn->recv) > 0) {
			s = buf_find(&conn->recv, 0, '\n', true);

			/* There already is a full line in the buffer */
			if (s != NULL) {
				/* ASCII NUL '\0'? */
				if (*s == '\0') {
					log_dbg(
						CONN_ID
						" ASCII NUL char found",
						conn_id(conn));
					dumppacket(LOG_ERR,
						   (uint8_t *)
						   buf_buffer(&conn->recv),
						   buf_cur(&conn->recv));
					buf_unlock(&conn->recv);
					/* Not acceptable in lines */
					return (-EINVAL);
				}

				len = (s - buf_buffer(&conn->recv)) + 1;

				/* Does it not fit? */
				if (len > buflen) {
					log_dbg(
						CONN_ID " line does not fit "
						"%" PRIu64 " > %u",
						conn_id(conn),
						len, buflen);
					buf_unlock(&conn->recv);
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

				log_dbg(
					CONN_ID " line = %" PRIu64,
					conn_id(conn), len);

				buf_unlock(&conn->recv);
				conn_unlock(conn);

				return (len);
			}
		}

		/* non-blocking socket? Then we are done */
		if (conn->connset != NULL) {
			log_dbg(
				CONN_ID " buffer empty",
				conn_id(conn));
			break;
		}

		log_dbg(
			CONN_ID " trying to get more",
			conn_id(conn));

		/* Receive more */
		i = conn_recvA(conn);
		if (i == 0) {
			/* Blocking socket, thus cannot happen */
			log_dbg(
				CONN_ID " blocked",
				conn_id(conn));
			fassert(false);
			break;
		} else if (i < 0) {
			/* Connection got closed etc */
			log_dbg(
				CONN_ID " closed (err = %d)",
				conn_id(conn), i);

			buf_unlock(&conn->recv);
			conn_unlock(conn);

			return (i);
		}
	}

	log_dbg(CONN_ID " nothing", conn_id(conn));

	buf_unlock(&conn->recv);
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
conn_ssl_send(conn_t *conn, const char *buf, uint64_t *len);
static bool
conn_ssl_send(conn_t *conn, const char *buf, uint64_t *len) {
	int	rc;

	log_dbg(CONN_ID " %u", conn_id(conn), (unsigned int)*len);

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
		log_dbg(CONN_ID " SSL_write %u/%u",
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
	       unsigned int nvec, uint64_t *len);
static bool
conn_ssl_sendv(conn_t *conn, const struct iovec *vec,
	       unsigned int nvec, uint64_t *len)
{
	bool		ret;
	uint64_t	written = 0;
	int		i;

	log_dbg(CONN_ID "", conn_id(conn));

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

	log_dbg(CONN_ID " wrote %" PRIu64, conn_id(conn), *len);

	return (true);
}
#endif /* CONN_SSL */

uint64_t
conn_flushleft(conn_t *conn) {
	uint64_t l;

	conn_lock(conn);
	buf_lock(&conn->send);
	buf_lock(&conn->send_headers);

	l = buf_cur(&conn->send) +
	    buf_cur(&conn->send_headers);

	buf_unlock(&conn->send_headers);
	buf_unlock(&conn->send);
	conn_unlock(conn);
	return (l);
}

static void
conn_sendfile_done(conn_t *conn);
static void
conn_sendfile_done(conn_t *conn) {
	conn->sendfile_len = 0;
	conn->sendfile_off = 0;

	assert(conn->sendfile_fd != -1);

	if (conn->sendfile_fd != -1) {
		close(conn->sendfile_fd);
		conn->sendfile_fd = -1;
	}
}

/*
 * Caller has to call conn_flush() separately
 * This so that headers can be added
 */
bool
conn_sendfile(conn_t *conn, const char *file) {
	int		fd;
	struct stat	st;

	/* Make sure there was nothing yet */
	assert(conn->sendfile_fd == -1);
	assert(conn->sendfile_off == 0);
	assert(conn->sendfile_len == 0);

	/* Check the path for strange ../ kind of constructs */
	if (strstr(file, "../") != NULL) {
		log_err(
			"Refusing '%s' which contains a relative path",
			file);
		return (false);
	}

	fd = open(file, O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_LARGEFILE);
	if (fd == -1) {
		log_err(
			"Could not open %s for sendfile()",
			file);
		return (false);
	}

#ifdef _DARWIN
	/*
	 * OSX 10.6 does not have a functioning O_CLOEXEC
	 * Thus work around it by doing this on all platforms
	 * even though 10.7+ handle it properly
	 *
	 * For 10.6 there remain a slight chance of a race
	 * here if another thread does an exec between the
	 * above open and the end of this call.
	 */
	if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
		log_err(
			"Could not set FD_CLOEXEC for %s",
			file);
	}
#endif /* _DARWIN */

	/* Get the file statistics */
	if (fstat(fd, &st) == -1) {
		log_err(
			"Could not fstat %s for sendfile()",
			file);
		close(fd);
		return (false);
	}

	/* Fill in our sendfile details */
	conn->sendfile_fd = fd;
	conn->sendfile_off = 0;
	conn->sendfile_len = st.st_size;

	/* For HTTP requests */
	conn_set_real_contentlen(conn, conn->sendfile_len);

	return (true);
}

static bool
conn_flush_sendfile(conn_t *conn);
static bool
conn_flush_sendfile(conn_t *conn) {
	off_t	off;
#ifdef _LINUX
	size_t	cnt;
#else
	off_t	cnt;
#endif
	int	r;

	log_dbg(
		CONN_ID " sendfile(%" PRIu64 "/%" PRIu64 ") (pre-flush)",
		conn_id(conn), conn->sendfile_off, conn->sendfile_len);

	off = conn->sendfile_off;
	cnt = conn->sendfile_len;
	cnt -= off;

	/*
	 * Note that this blocks on input,
	 * but we assume disk IO to be faster than network IO
	 * Also, we have multiple worker threads thus it ain't that bad
	 */
#ifdef _LINUX
	/* Linux */
	r = sendfile(conn->sock, conn->sendfile_fd, &off, cnt);
#else
	/* Darwin/BSD variants */
	r = sendfile(conn->sendfile_fd, conn->sock, off, &cnt, NULL, 0);
#endif
	if (r == -1) {
		/* On Linux an error is a hard error, no progress is made */
#ifndef _LINUX
		switch (errno) {
		case EAGAIN:
			/* We are non-blocking, thus expected */
			break;
		default:
#endif
			/* Something broken */
			log_err(
				CONN_ID " sendfile() failed",
				conn->id);
			conn_sendfile_done(conn);
			return (false);
#ifndef _LINUX
		}

		/* Should always go forward */
		assert((uint64_t)off >= conn->sendfile_off);

		/* Store our new offset */
		conn->sendfile_off += cnt;

		log_dbg(
			CONN_ID " sendfile(%" PRIu64 "/"
			"%" PRIu64 ") = %0.2f%%",
			conn_id(conn),
			conn->sendfile_off,
			conn->sendfile_len,
			(float)conn->sendfile_off * 100 / (float)conn->sendfile_len);
#endif
	} else {
		assert(r >= 0);
#ifdef _LINUX
		/* Linux stores the new offset in off */
		conn->sendfile_off = off;

		log_dbg(
			CONN_ID " sendfile(%" PRIu64 "/"
			"%" PRIu64 ") = %0.2f%%",
			conn_id(conn),
			conn->sendfile_off,
			conn->sendfile_len,
			(float)conn->sendfile_off * 100 / (float)conn->sendfile_len);

		/* Done? */
		if (conn->sendfile_off >= conn->sendfile_len)
		{
#endif
		conn_sendfile_done(conn);

		log_dbg(CONN_ID " flush complete", conn_id(conn));

		/* Nothing to flush thus continue polling for incoming */
		conn_eventsA(conn, CONN_POLLIN);
#ifdef _LINUX
		}
#endif
	}

	return (true);
}

/*
 * Flush a bit more of the buffer towards the client
 * Might be async and not flush everything
 */
bool
conn_flush(conn_t *conn) {
	ssize_t		r;
	uint64_t	len, len_b, len_h, wlen;
	bool		ret = true;

	log_dbg(
		CONN_ID " list: %s",
		conn_id(conn),
		connset_list(conn->connset, conn->connset_l));

	conn_lock(conn);
	buf_lock(&conn->send);
	buf_lock(&conn->send_headers);

#ifdef CONN_SSL
	if (!conn_ssl_flush(conn)) {
		/* Still need to flush the SSL buffer */
		/* Thus don't do anything else here yet */
		log_dbg(CONN_ID " SSL flush needed", conn_id(conn));
		buf_unlock(&conn->send_headers);
		buf_unlock(&conn->send);
		conn_unlock(conn);
		return (true);
	}
#endif /* CONN_SSL */

	if (!conn_is_connected(conn) || conn_is_eofA(conn)) {
		log_dbg(CONN_ID " not connected", conn_id(conn));
		buf_unlock(&conn->send_headers);
		buf_unlock(&conn->send);
		conn_unlock(conn);
		return (false);
	}

	len_b = buf_cur(&conn->send);
	len_h = buf_cur(&conn->send_headers);
	len = len_b + len_h;

	/* Nothing to flush */
	if (len == 0) {
		buf_unlock(&conn->send_headers);
		buf_unlock(&conn->send);

		/* Need to send more of a file? */
		if (conn->sendfile_len != 0) {
			ret = conn_flush_sendfile(conn);
		} else {
			log_dbg(CONN_ID " nothing to flush", conn_id(conn));

			/* Nothing to flush thus continue polling for incoming */
			conn_eventsA(conn, CONN_POLLIN);
		}

		conn_unlock(conn);
		return (ret);
	}

	conn->last_sent = gettime();

	/* Call the flush hook */
	if (conn->flush_hook) {
		if (len_h > 0) {
			conn->flush_hook(conn->flush_data,
					 conn_id(conn), true,
					 buf_buffer(&conn->send_headers),
					 len_h);
		}

		if (len_b > 0) {
			conn->flush_hook(conn->flush_data,
					 conn_id(conn), false,
					 buf_buffer(&conn->send),
					 len_b);
		}
	}

	if (len_h > 0) {
		struct iovec	iovec[2];
		unsigned int	iolen;

		/* Add separating when we didn't yet \n */
		fassert((len_b + len_h) != 0);

		if (conn->real_contentlen > 0 || len_b > 0) {
			if (len_b > 0) {
				log_dbg(
					CONN_ID " Have Content-Length: %" PRIu64,
					conn_id(conn), len_b);
			}

			if (conn->real_contentlen != 0) {
				log_dbg(CONN_ID
					" Real Content-Length: %" PRIu64,
					conn_id(conn), conn->real_contentlen);
			}

			conn_addheaderf(conn,
				"Content-Length: %" PRIu64,
				conn->real_contentlen > 0 ?
					conn->real_contentlen :
					len_b);

			/* Reset it to avoid re-use */
			conn->real_contentlen = 0;
		}

		/* Separate header from body */
		conn_addheader(conn, "");

		/* We added some headers, thus this became larger */
		len_h = buf_cur(&conn->send_headers);
		len = len_b + len_h;

		log_dbg(
			CONN_ID " "
			"Full HEADERs (%" PRIu64 " vs %" PRIsizet ")",
			conn_id(conn),
			len_h,
			strlen(buf_buffer(&conn->send_headers)));
		log_dbg("8<-----------");
		log_dbg("%s", buf_buffer(&conn->send_headers));
		log_dbg("----------->8");

		/* The chunks to send */
		iovec[0].iov_base = buf_buffer(&conn->send_headers);
		iovec[0].iov_len = len_h;
		iovec[1].iov_base = buf_buffer(&conn->send);
		iovec[1].iov_len = len_b;

		/* Sometimes we do not have content thus we skip that one */
		iolen = iovec[1].iov_len > 0 ? 2 : 1;

		log_dbg(CONN_ID " Flushing %" PRIu64 " (h)",
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
		wlen = len_b;
		log_dbg(CONN_ID " Flushing %" PRIu64, conn_id(conn), len);

#ifdef CONN_SSL
		if (conn->ssl) {
			r = conn_ssl_send(conn, buf_buffer(&conn->send), &wlen);
		} else {
#endif
			fassert(conn_is_valid(conn));
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
		/*
		 * While this is an 'error', they just mean
		 * the connection was closed while sending
		 * and thus can be normally handled
		 */
#ifdef CONN_SSL
		log_dbg(CONN_ID " %sFlush error = %" PRIsizet,
			conn->ssl ? "SSL " : "",
			conn_id(conn), r);
#else
		log_dbg(CONN_ID " Flush error = %" PRIsizet,
			conn_id(conn), r);
#endif

		buf_unlock(&conn->send_headers);
		buf_unlock(&conn->send);
		conn_unlock(conn);
		return (false);
	}

	if (wlen == len) {
		log_dbg(CONN_ID " Written all", conn_id(conn));

		/* Nothing further to send */
		buf_empty(&conn->send);
		buf_empty(&conn->send_headers);

		/* Need to send more of a file? */
		if (conn->sendfile_len != 0) {
			ret = conn_flush_sendfile(conn);
		} else {
			log_dbg(CONN_ID " nothing to flush", conn_id(conn));

			/* Nothing to flush thus continue polling for incoming */
			conn_eventsA(conn, CONN_POLLIN);
		}
	} else {
		log_dbg(
			CONN_ID " Written %" PRIu64 " of %" PRIu64 ", left: %" PRIu64,
			conn_id(conn), wlen, len, len - wlen);

		/* Headers will go first */
		if (len_h > 0) {
			if (wlen >= len_h) {
				/* Done with the headers */
				wlen -= len_h;
				buf_empty(&conn->send_headers);
			} else {
				/* Move rest to the front of the buffer */
				buf_shift(&conn->send_headers, wlen);
				len_h -= wlen;
				wlen = 0;
			}
		}

		/* Bytes left from the normal buffer? */
		if (wlen > 0) {
			fassert(wlen < len_b);
			/* Move the rest to the front of the buffer */
			buf_shift(&conn->send, wlen);
			len_b -= wlen;
			wlen = 0;
		}

		/* Try to get it out there */
		conn_eventsA(conn, CONN_POLLIN | CONN_POLLOUT);
	}

	log_dbg(
		CONN_ID " left: h: %" PRIu64 ", b: %"  PRIu64 ", sf: %" PRIu64,
		conn_id(conn),
		len_h, len_b,	
		conn->sendfile_len);

	buf_unlock(&conn->send_headers);
	buf_unlock(&conn->send);
	conn_unlock(conn);

	return (ret);
}

/* Callers might have locked the conn mutex */
bool
conn_addheaders(conn_t *conn, const char *txt) {
	bool ret;

	buf_lock(&conn->send_headers);
	ret = buf_put(&conn->send_headers, txt);
	buf_unlock(&conn->send_headers);

	return (ret);
}

/* Callers might have locked the conn mutex */
bool
conn_addheader(conn_t *conn, const char *txt) {
	bool ret;

	buf_lock(&conn->send_headers);
	ret = buf_put(&conn->send_headers, txt);
	if (ret) ret = buf_put(&conn->send_headers, "\r\n");
	buf_unlock(&conn->send_headers);

	return (ret);
}

/* Callers might have locked the conn mutex */
bool
conn_addheaderf(conn_t *conn, const char *fmt, ...) {
        va_list		ap;
	bool		ret;
#ifdef DEBUG
	uint64_t	cur;
#endif

	buf_lock(&conn->send_headers);

        va_start(ap, fmt);

#ifdef DEBUG
	cur = buf_cur(&conn->send_headers);
#endif
	ret = buf_vprintf(&conn->send_headers, fmt, ap);

	log_dbg(CONN_ID " (len=%" PRIu64 ") %s",
		conn_id(conn), buf_cur(&conn->send_headers) - cur,
		&buf_buffer(&conn->send_headers)[cur]);

	if (ret) ret = buf_put(&conn->send_headers, "\r\n");

	va_end(ap);

	buf_unlock(&conn->send_headers);

	return (ret);
}

bool
conn_putl(conn_t *conn, const char *txt, unsigned int len) {
	bool		ret;
	uint64_t	cur;

	if (len == 0)
		return (true);

	conn_lock(conn);
	buf_lock(&conn->send);
	buf_lock(&conn->send_headers);

	cur = buf_cur(&conn->send);
	ret = buf_putl(&conn->send, txt, len);

	if (ret) {
		log_dbg(CONN_ID ": %u", conn_id(conn), len);

		debugpacket(	(uint8_t *)&buf_buffer(&conn->send)[cur],
				buf_cur(&conn->send) - cur);
	}

	buf_unlock(&conn->send_headers);
	buf_unlock(&conn->send);
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
	bool		ok;

	/* How much is in the buffer? */
	len = conn_buffer_cur(in);

	if (len == 0) {
		/* Nothing there */
		return (0);
	}

	/* Only copy upto 'max' bytes */
	if (len > max) {
		len = max;
	}

	/* Copy the received buffer from the in to the out */
	ok = conn_putl(out, conn_buffer(in), len);

	/* All okay */
	if (ok) {
		/* Input has been processed */
		conn_buffer_shift(in, len);
	}

	return (ok ? len : 0);
}

bool
conn_vprintf(conn_t *conn, const char *fmt, va_list ap) {
	bool		ret;
	uint64_t	cur;

	fassert(conn_is_valid(conn));

	conn_lock(conn);
	buf_lock(&conn->send);
	buf_lock(&conn->send_headers);

	cur = buf_cur(&conn->send);
	ret = buf_vprintf(&conn->send, fmt, ap);

	if (ret) {
		log_dbg(CONN_ID "", conn_id(conn));

		debugpacket(	(uint8_t *)&buf_buffer(&conn->send)[cur],
				buf_cur(&conn->send) - cur);
	}

	buf_unlock(&conn->send_headers);
	buf_unlock(&conn->send);
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
	fassert(connset != NULL);

	type = (protocol == IPPROTO_TCP ? SOCK_STREAM : SOCK_DGRAM);
	snprintf(service, sizeof service, "%u", port);

	log_dbg(
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
		log_ntc("getaddrinfo() failed: %s", gai_strerror(n));
		return (false);
	}

	ressave = res;

	while (res) {
		/* No errors this round yet */
		errfunc = NULL;

		sock = socket(res->ai_family,
#ifdef SOCK_CLOEXEC
			      SOCK_CLOEXEC |
#endif
			      res->ai_socktype,
			      res->ai_protocol);

		if (sock != INVALID_SOCKET) {
#ifndef SOCK_CLOEXEC
#ifdef FD_CLOEXEC
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

					log_dbg("Listening on %s",
						buf);

					conn = (conn_t *)mcalloc(sizeof *conn,
								 "conn");
					if (!conn) {
						log_crt(
							"No mem for conn");
						break;
					}

					if (!conn_init(conn, NULL)) {
						log_err(
							"Conn init failed");
						break;
					}

					conn->sock = sock;
					conn->protocol = protocol;
					conn->port = port;

					/* Always non-blocking */
					conn_set_nonblocking(conn);

					/* Lock it up */
					conn_lock(conn);

					/* The connset this belongs to */
					conn_set_connset(conn, connset);

					/* Mark it as listening */
					conn_set_state(conn, CONN_LISTENING);

					/* We expect inbound connections  */
					conn_eventsA(conn, CONN_POLLIN);

					/* Release it */
					conn_unlock(conn);

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

			log_ntc("Couldn't %s() on %s", errfunc, buf);

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
 *
 * We use connected sockets even for datagram connections
 *
 * Depending if a connset is given the connection is blocking or not
 */
bool
conn_create_connection(conn_t *conn, const char *hostname,
		       uint32_t protocol, uint32_t port,
		       connset_t *connset) {
	struct addrinfo		hints, *res, *ressave = NULL;
	char			service[32], buf[128];
	unsigned int		type;
	int			n;

	fassert(conn_is_there(conn));
	fassert(hostname != NULL);
	fassert(port != 0);

	snprintf(service, sizeof service, "%u", port);

	conn_lock(conn);

	log_dbg(CONN_ID " (%s:%s) [%sblocking]",
		conn_id(conn), hostname, service, connset ? "non" : "");

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
		log_ntc("\"%s\":\"%s\" - getaddrinfo error: [%s]",
			hostname, service, gai_strerror(n));
		conn_unlock(conn);
		return (false);
	}

	ressave = res;

	while (res) {
		/* Get a human readable string */
		inet_rtop(res, buf, sizeof buf);

		log_dbg("Attempting connect to %s:%u:%u (%s)",
					hostname, protocol, port, buf);

		conn->sock = socket(res->ai_family,
#ifdef SOCK_CLOEXEC
				    SOCK_CLOEXEC |
#endif
			            res->ai_socktype,
			            res->ai_protocol);

		if (conn->sock != INVALID_SOCKET) {
			log_dbg("Socket " SOCK_ID,
				conn_sock(conn));
#ifndef SOCK_CLOEXEC
#ifdef FD_CLOEXEC
			/*
			 * Ensure FD_CLOEXEC is set for platforms
			 * without SOCK_CLOEXEC
			 */
			fcntl(conn->sock, F_SETFD, FD_CLOEXEC);
#endif
#endif
			/* No events for now */
			conn_eventsA(conn, CONN_POLLNONE);

			/* To block or to not to block? */
			if (connset != NULL)
				conn_set_nonblocking(conn);
			else
				conn_set_blocking(conn);

			n = connect(conn->sock, res->ai_addr,
				    (int)res->ai_addrlen);

			if (	n == 0 ||
				(connset && n == -1 && errno == EINPROGRESS))
			{
				/* Connected */
				log_dbg("Connected (%s:%u:%u)%s",
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

				break;
			} else {
				log_ntc(
					"Failed to connect to %s %d/%d",
					buf, errno, EINPROGRESS);
				closesocket(conn->sock);
				conn->sock = INVALID_SOCKET;
			}
		} else {
			log_err("Couldn't get a socket for %s", buf);
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
 * Note that this is a blocking version as no connset gets provided
 */
bool
conn_connect(conn_t *conn, const char *host,
	     unsigned int protocol, unsigned int port) {

	return (conn_create_connection(conn, host, protocol, port, NULL));
}

/* Note that this does not set any events, the caller has to do that */
bool
conn_accept(conn_t *conn, conn_t *lconn, void *clientdata) {
	char		address[256];
	uint32_t	protocol, port;

	fassert(conn);
	fassert(conn->sock == INVALID_SOCKET);

	fassert(lconn);
	fassert(lconn->sock != INVALID_SOCKET);

	/* Setup the context */
	conn_lock(lconn);
	conn_lock(conn);

	/* Mark that it is accepting a new connection */
	conn_set_state(conn, CONN_ACCEPTING);

	/* Accept the socket */
#ifdef _LINUX
	conn->sock = accept4(lconn->sock, NULL, 0, SOCK_CLOEXEC | SOCK_NONBLOCK);
#else
	conn->sock = accept(lconn->sock, NULL, 0);
#endif

	conn_unlock(lconn);

	if (conn->sock == INVALID_SOCKET) {
		log_err(CONN_ID " failed accept", conn_id(conn));
		conn_unlock(conn);
		return (false);
	}

	log_dbg(
		CONN_ID " accepted " SOCK_ID,
		conn_id(conn), conn_sock(conn));

#ifndef _LINUX
#ifndef _WIN32
	/* Ensure FD_CLOEXEC is set for platforms without accept4() */
	fcntl(conn->sock, F_SETFD, FD_CLOEXEC);
#endif
#endif

	if (lconn->connset != NULL) {
		/* Take over the connset from the listening socket */
		conn_set_connset(conn, lconn->connset);

		/* Make us nonblocking too */
		conn_set_nonblocking(conn);
	}

	conn->protocol	= lconn->protocol;
	conn->port	= lconn->port;
	conn->clientdata= clientdata;

	conn_unlock(conn);

	conn_getinfo(conn, false, address, sizeof address, &protocol, &port);

	log_dbg(
		CONN_ID " accepted connection from %s, proto %u, port %u",
		conn_id(conn), address, protocol, port);

	conn_getinfo(conn, true, address, sizeof address, &protocol, &port);

	log_dbg(
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

	fassert(conn_is_valid(conn));

	memzero(hostname, hlen);
	*proto = 0;
	*port = 0;

	memzero(&ss, sizeof ss);
	if (local)
		r = getsockname(conn->sock, (struct sockaddr *)&ss, &sslen);
	else
		r = getpeername(conn->sock, (struct sockaddr *)&ss, &sslen);
	if (r != 0) {
		log_wrn(CONN_ID " could not get%sname",
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
		log_crt(CONN_ID " Unsupported AF %u",
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
		log_err(CONN_ID " SSL_new() failed", conn_id(conn));
		return (false);
	}

	/* We want to find ourselves again */
	SSL_set_app_data(conn->ssl, conn);

	conn->ssl_bio_in = BIO_new(BIO_s_mem());
	if (!conn->ssl_bio_in) {
		log_err(CONN_ID " BIO_new(in) failed", conn_id(conn));
		return (false);
	}
	BIO_set_nbio(conn->ssl_bio_in, 1);
	BIO_set_callback(conn->ssl_bio_in, conn_ssl_bio_cb);
	BIO_set_callback_arg(conn->ssl_bio_in, (char *)conn);

	conn->ssl_bio_out = BIO_new(BIO_s_mem());
	if (!conn->ssl_bio_out) {
		log_err(CONN_ID " BIO_new(out) failed", conn_id(conn));
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

		log_dbg(CONN_ID " Attempting SSL Client Handshake",
			conn_id(conn));

		/* Do handshaky stuff */
		SSL_set_connect_state(conn->ssl);

		/* Arbitrary limit of 42 so we do not loop forever */
		for (loops = 0; loops < 42 && !done; loops++) {
			log_dbg(
				CONN_ID " ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~",
				conn_id(conn));
			rc = SSL_connect(conn->ssl);

			done = (rc == 1) && SSL_is_init_finished(conn->ssl);

			if (!done) {
				se  = SSL_get_error(conn->ssl, rc);

				switch (se) {
				case SSL_ERROR_NONE:
					log_wrn(
						CONN_ID " ERR: NONE",
						conn_id(conn));
					return (false);

				case SSL_ERROR_WANT_READ:
					log_wrn(
						CONN_ID " Want Read",
						conn_id(conn));
					conn_recvA(conn);
					break;

				case SSL_ERROR_WANT_WRITE:
					log_wrn(
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
			log_wrn(
				CONN_ID " SSL Client Handshake Failure",
				conn_id(conn));
			return (false);
		}

		/* All okay */
		log_dbg(
			CONN_ID " SSL Client Handshake OK", conn_id(conn));
	}

	return (true);
}

#endif /* CONN_SSL */
