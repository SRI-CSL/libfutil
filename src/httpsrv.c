/* HTTP Server */

#include <libfutil/misc.h>
#include <libfutil/conn.h>
#include <libfutil/httpsrv.h>

/*
 * XXX: Disconnect idle connections if they are idle too long
 */

/* Internal. */

#define HTTPH(h) offsetof(httpsrv_headers_t, h), sizeof (((httpsrv_headers_t *)NULL)->h)

misc_map_t httpsrv_headers[] = {
	{ "Host",		HTTPH(hostname)		},
	{ "Cookie",		HTTPH(cookie)		},
	{ "Content-Type",	HTTPH(content_type)	},
	{ "Content-Length",	HTTPH(content_length_s)	},
	{ NULL,			0, 0 }
};

/* XXX: order alpha and then bisect search */
/* Keep in sync with above list */
struct http_method http_methods[] = {
	{ "",		0 },
	{ "GET",	3 },
	{ "HEAD",	4 },
	{ "POST",	4 },
	{ "PUT",	3 },
	{ "DELETE",	6 },
	{ "TRACE",	5 },
	{ "OPTIONS",	7 },
	{ "CONNECT",	7 },
	{ "PATCH",	5 },
};

const char *
httpsrv_methodname(unsigned int method) {
	/* To make sure that at least the list size is synced */
	assert(HTTP_M_MAX == lengthof(http_methods));

	if (method >= lengthof(http_methods)) {
		logline(log_CRIT_, "Unknown HTTP method '%u'", method);
		return ("<UNKNOWN>");
	}

	return (http_methods[method].name);
}

void
httpsrv_set_userdata(httpsrv_client_t *hcl, void *user) {
	hcl->user = user;
}

void
httpsrv_close(httpsrv_client_t *hcl) {
	hcl->close = true;
}

void
httpsrv_client_close(httpsrv_client_t *hcl);
void
httpsrv_client_close(httpsrv_client_t *hcl) {
	logline(log_DEBUG_, "Closing session " CONN_ID, conn_id(&hcl->conn));

	if (hcl->hs->close)
		hcl->hs->close(hcl, hcl->user);

	/* Cleanup the headers */
	buf_destroy(&hcl->the_headers);

	/* Flush & Close the connections */
	if (conn_is_there(&hcl->conn)) {
		conn_flush(&hcl->conn);
		conn_destroy(&hcl->conn);
	}

	mfree(hcl, sizeof *hcl, "httpsrv_client_t");
}

static void
httpsrv_error(httpsrv_client_t *hcl, unsigned int ecode, const char *msg);
static void
httpsrv_error(httpsrv_client_t *hcl, unsigned int ecode, const char *msg) {
	conn_addheaderf(&hcl->conn, "HTTP/1.1 %u %s\r\n", ecode, msg);
}

static void
httpsrv_handle_http(httpsrv_client_t *hcl) {
	char		line[4096];
	int		i;
	unsigned int	l, m;
	uint32_t	t32;
	uint64_t	t64;

	/* As long as we got lines parse them */
	while (true) {

		/* Forwarding the body? */
		if (hcl->bodyfwd) {
			/* Copy some more */
			t64 = conn_copym(&hcl->conn,
					&hcl->bodyfwd->conn,
					hcl->bodyfwdlen);

			logline(log_DEBUG_,
					CONN_ID " BodyFwd %" PRIu64,
					conn_id(&hcl->conn), t64);

			/* Some bits less */
			assert(t64 <= hcl->bodyfwdlen);
			hcl->bodyfwdlen -= t64;

			/* Done or something went wrong? */
			if (hcl->bodyfwdlen == 0 || t64 == 0) {
				logline(log_DEBUG_,
						CONN_ID " BodyFwd Done",
						conn_id(&hcl->conn));

				/* Inform the caller */
				assert(hcl->hs->bodyfwddone);
				hcl->hs->bodyfwddone(hcl, hcl->user);

				/* Done with this */
				hcl->bodyfwd = NULL;
				hcl->bodyfwdlen = 0;

				/* Request is done */
				httpsrv_done(hcl);
			}

			/* Done with this for now */
		}

		/* There should be something in this buffer */
		i = conn_recvline(&hcl->conn, line, sizeof line);
		if (i == 0) {
			logline(log_DEBUG_,
				CONN_ID " No new line yet",
				conn_id(&hcl->conn));

			/* Try to get more lines */
			i = conn_recv(&hcl->conn);
			if (i == 0)
				return;

			/* Try again to get the line */
			if (i > 0)
				continue;

			/* Drop through to failure below */
		}

		if (i < 0) {
			logline(log_DEBUG_, "Receive line problem, closing");
			/* Remote end closed socket */
			hcl->close = true;
			return;
		}

		l = i;

		/* Empty line == end of command */
		if (l == 1 && line[0] == '\n') {
			logline(log_DEBUG_, "Got an empty line");

			/* Stray \n, ignore it */
			if (strlen(hcl->the_request) == 0) {
				continue;
			}

			/*
			 * Note: for POST we read in the body when the caller wants it
			 * If it is not read we read it in at 'done' time
			 */

			/* Convert the port number strings into numbers */
			if (sscanf(hcl->headers.local_port_s, "%u", &t32) == 1 &&
				t32 != 0) {
				hcl->headers.local_port = t32;
			} else {
				logline(log_DEBUG_, "No Local Port found");
			}

			if (sscanf(hcl->headers.remote_port_s, "%u", &t32) == 1 &&
				t32 != 0) {
				hcl->headers.remote_port = t32;
			} else {
				logline(log_DEBUG_, "No Remote Port found");
			}

			/* Post? Requires a content-length */
			if (hcl->method == HTTP_M_POST) {
				if (sscanf(hcl->headers.content_length_s,
					   "%" PRIu64, &t64) == 1) {
					hcl->headers.content_length = t64;
				} else {
					logline(log_DEBUG_,
						"POST without Content-Length");
					httpsrv_error(hcl, 400,
						"POST without Content-Length");
					hcl->close = true;
				}
			}

			/* Another request fed in */
			hcl->reqid++;

			/* Process it */
			assert(hcl->hs->handle);
			logline(log_DEBUG_, "handling");
			hcl->hs->handle(hcl, hcl->user);
			logline(log_DEBUG_, "handling complete");

			/* Next */
			continue;
		}

		/* Remove trailing \n */
		line[--l] = '\0';

		logline(log_DEBUG_, "got line (len=%u) : %s", l, line);

		/* No method yet? */
		if (hcl->method == HTTP_M_NONE) {
			for (m = 0; m < lengthof(http_methods); m++) {
				if (strncasecmp(line, http_methods[m].name,
						http_methods[m].len) != 0 ||
				    line[http_methods[m].len] != ' ') {
					continue;
				}

				hcl->method = m;
				break;
			}

			if (hcl->method == HTTP_M_NONE) {
				logline(log_NOTICE_, "Unknown HTTP: %s", line);
				httpsrv_error(hcl, 400, "Unknown HTTP method");
				hcl->close = true;
				return;
			}

			if (l >= sizeof hcl->the_request) {
				logline(log_NOTICE_, "Request Too Big: %s", line);
				httpsrv_error(hcl, 400, "Request Too Big"); /* XXX: correct HTTP code */
				hcl->close = true;
				return;
			}

			/* Store the request for later parsing */
			memcpy(hcl->the_request, line, l);
			hcl->the_request[l] = '\0';
			continue;
		}

		/* Add headers to the raw headers */
		buf_putl(&hcl->the_headers, line, l);
		buf_putl(&hcl->the_headers, "\r\n", 2);

		/* Parse the header line */
		misc_map(line, httpsrv_headers, (char *)&hcl->headers);

		/* Does the caller want headers? */
		if (hcl->hs->header)
			hcl->hs->header(hcl, hcl->user, line);
	}
}

void
httpsrv_done(httpsrv_client_t *hcl) {
	logline(log_DEBUG_, CONN_ID " is done", conn_id(&hcl->conn));

	/* Call the client's done function */
	if (hcl->hs->done)
		hcl->hs->done(hcl, hcl->user);

	/* Flush the output */
	conn_flush(&hcl->conn);

	/* No method yet */
	hcl->method = HTTP_M_NONE;

	/* Last activity */
	hcl->lastact = gettime();

	/* Empty Request */
	memzero(&hcl->the_request, sizeof hcl->the_request);

	/* Clear incoming parsed header state */
	memzero(&hcl->headers, sizeof hcl->headers);

	/* Empty raw headers */
	buf_empty(&hcl->the_headers);

	/* No arguments yet either */
	hcl->headers.argc = 0;

	/* Reset */
	hcl->close = false;
	hcl->busy = false;
	hcl->bodyfwd = NULL;
	hcl->bodyfwdlen = 0;

	/* Tell it to try to output (flush) */
	conn_events(&hcl->conn, CONN_POLLIN | CONN_POLLOUT);

	/*
	 * This cl connection is now ready for the next request
	 * which could be in the buffer already due to HTTP pipelining
	 *
	 * Thus try to parse more lines if there are more already
	 */
	if (!(conn_buffer_isempty(&hcl->conn))) {
		logline(log_DEBUG_, CONN_ID " has data in receive buffer",
			conn_id(&hcl->conn));

		httpsrv_handle_http(hcl);
	} else {
		logline(log_DEBUG_, CONN_ID " has nothing queued",
			conn_id(&hcl->conn));
	}
}

bool
httpsrv_parse_request(httpsrv_client_t *hcl) {
	unsigned int	j, ao = 0, uo = 0;
	char		c, *line = hcl->the_request;
	bool		isarg = false;

	/* Only parse it once */
	if (hcl->headers.args[0] != '\0') {
		logline(log_DEBUG_, CONN_ID " Not parsing again",
			conn_id(&hcl->conn));
		return (true);
	}

	logline(log_DEBUG_, CONN_ID " scanning: %s", conn_id(&hcl->conn), line);

	assert(sizeof hcl->headers.argsplit == sizeof hcl->headers.args);

	/* Nothing found yet */
	hcl->headers.argc = 0;
	memzero(hcl->headers.argi, sizeof hcl->headers.argi);
	hcl->headers.argi[0].var = hcl->headers.argsplit;

	/* First skip over the method */
	for (j = 0; line[j] != ' '; j++);

	/* Skip over the space behind the method */
	j++;

	for (	;
		uo < (sizeof hcl->headers.uri - 1) &&
		ao < (sizeof hcl->headers.args - 1);
		j++) {

		assert(hcl->headers.argc < lengthof(hcl->headers.argi));

		c = line[j];

		if (c == ' ' || c == '\0') {
			/* Was the last argument used at least a bit? */
			if (strlen(
				hcl->headers.argi[hcl->headers.argc].var) > 0)
				hcl->headers.argc++;
				if (hcl->headers.argc >=
					lengthof(hcl->headers.argi)) {
					logline(log_NOTICE_, CONN_ID " Too many args",
						conn_id(&hcl->conn));
					httpsrv_error(hcl, 400, "Too many args");
					return (false);
				}
			break;
		} else if (c == '?') {
			/* The rest is arguments */
			isarg = true;
			continue;
		} else if (c == '%') {
			/* Escaped */
			if (!isxdigit(line[j+1]) || !isxdigit(line[j+2])) {
				logline(log_NOTICE_, CONN_ID " Broken URL: %s",
					conn_id(&hcl->conn), line);
				httpsrv_error(hcl, 400, "Broken URL");
				return (false);
			}

			/* Unescape URL (eg %2f -> '/') */
			c =  ((line[j+1] >= 'A') ?
					((line[j+1] & 0xdf) - 'A') +
					10 :
					(line[j+1] - '0'));
			c *= 16;
			c += ((line[j+2] >= 'A') ?
					((line[j+2] & 0xdf) - 'A') +
					10 :
					(line[j+2] - '0'));

			/* skip over the two hex digits */
			/* The for skips over the % */
			j += 2;
		}

		if (!isarg)
			hcl->headers.uri[uo++] = c;
		else {
			/* Next argument? */
			if (c == '&') {
				hcl->headers.argsplit[ao]
					=  '\0';
				hcl->headers.argc++;

				if (hcl->headers.argc >=
					lengthof(hcl->headers.argi)) {
					logline(log_NOTICE_,
						CONN_ID "Too many args",
						conn_id(&hcl->conn));
					httpsrv_error(hcl, 400, "Too many args");
					return (false);
				}

				/* The variable starts here */
				hcl->headers.argi[hcl->headers.argc].var
					= &hcl->headers.argsplit[ao+1];
			}

			/* Value? */
			else if (c == '=') {
				/* Terminate it */
				hcl->headers.argsplit[ao] = '\0';

				/* The value starts here */
				hcl->headers.argi[hcl->headers.argc].val
					= &hcl->headers.argsplit[ao+1];
			/* Data */
			} else {
				/* Just add it to the string */
				hcl->headers.argsplit[ao] = c;
			}

			/* Next argchar */
			hcl->headers.args[ao++] = c;
		}
	}

	/* Note that this client hit us */
	logline(log_DEBUG_,
		CONN_ID "\n"
		"HTTP: the_request: %s (%u)\n"
		"HTTP: hostname: %s\n"
		"HTTP: uri: %s\n"
		"HTTP: local: %s/%u\n"
		"HTTP: remote: %s/%u",
		conn_id(&hcl->conn),
		hcl->the_request, (unsigned int)strlen(hcl->the_request),
		hcl->headers.hostname,
		hcl->headers.uri,
		hcl->headers.local_ip, hcl->headers.local_port,
		hcl->headers.remote_ip, hcl->headers.remote_port);

	logline(log_DEBUG_, CONN_ID " Got %u arguments:",
		conn_id(&hcl->conn),
		hcl->headers.argc);

	for (j = 0; j < hcl->headers.argc; j++) {
		logline(log_DEBUG_,
			CONN_ID " Arg %u :: %s = %s",
			conn_id(&hcl->conn),
			j,
			hcl->headers.argi[j].var,
			hcl->headers.argi[j].val);
	}

	logline(log_DEBUG_, CONN_ID " args = %s",
		conn_id(&hcl->conn), hcl->headers.args);

	return (true);
}

void
httpsrv_args(httpsrv_client_t *hcl, httpsrv_argl_t *a) {
	unsigned int i, j;

	/* Parse the request in case it was not done yet */
	httpsrv_parse_request(hcl);

	/* Lookup all the arguments */
	for (i=0; a[i].var; i++) {

		/* Skip optional arguments */
		if (!a[i].val)
			continue;

		/* Per default there is no value */
		*a[i].val = NULL;

		/* Try to match it up */
		for (j = 0; j < hcl->headers.argc; j++)
		{
			if (strcasecmp(hcl->headers.argi[j].var,
				       a[i].var) != 0)
				continue;

			/* Found it */
			*a[i].val = hcl->headers.argi[j].val;
			break;
		}
	}
}

/* Accept incoming client connections */
static void
httpsrv_accept(conn_t *lconn, httpsrv_t *hs) {
	/* Unique number, for easy debugging */
	static uint64_t		cl_id = 0;

	httpsrv_client_t	*hcl;
	char			address[256];
	uint32_t		proto, port;

	logline(log_DEBUG_, "[d%" PRIu64 "]", hs->id);

	/* Create a cl session */
	hcl = mcalloc(sizeof *hcl, "httpsrv_client_t");
	if (hcl == NULL) {
		logline(log_CRIT_, "alloc failed");
		return;
	}

	/* Identity */
	hcl->id = ++cl_id;

	/* When did this start & last activity */
	hcl->starttime = hcl->lastact = gettime();

	/* We share the same database connection over all contexts */
	/* Could swap this out later to per-thread etc */
	hcl->hs = hs;

	/* Initialize the conn to defaults */
	if (!conn_init(&hcl->conn, NULL)) {
		logline(log_CRIT_, "Could not init connections");
		httpsrv_client_close(hcl);
		return;
	}

	/* Init the buffers */
	if (!buf_init(&hcl->the_headers)) {
		logline(log_CRIT_, "Could not init buf");
		httpsrv_client_close(hcl);
		return;
	}

	/* Accept the socket */
	if (!conn_accept(&hcl->conn, lconn, hcl)) {
		logline(log_NOTICE_, "conn_accept()");
		httpsrv_client_close(hcl);
		return;
	}

	/* Who is it on our side? */
	conn_getinfo(&hcl->conn, true, address, sizeof address, &proto, &port);

	/* We expect to receive something from it */
	conn_events(&hcl->conn, CONN_POLLIN);

	/* Register this session in our sessions list */
	list_addtail_l(&hs->sessions, &hcl->node);

	/* User supplied function */
	if (hcl->hs->accept)
		hcl->hs->accept(hcl, hcl->hs->user);

	return;
}

/* Receive hcl commands */
static void
httpsrv_receive(httpsrv_client_t *hcl, conn_t *conn) {
	int i;

	logline(log_DEBUG_, CONN_ID, conn_id(&hcl->conn));

	/* This is a non-blocking socket thus receive a bit */
	i = conn_recv(conn);
	if (i == 0) {
		logline(log_DEBUG_,
			CONN_ID " nothing more",
			conn_id(&hcl->conn));
	} else if (i < 0) {
		logline(log_DEBUG_,
			CONN_ID " Remote end closed connection",
			conn_id(&hcl->conn));
		hcl->close = true;
	} else {
		if (hcl->busy) {
			logline(log_DEBUG_,
				CONN_ID " Busy processing request",
				conn_id(&hcl->conn));
			return;
		}

		/* HTTP Connection */
		logline(log_DEBUG_,
			CONN_ID " Try to parse some lines",
			conn_id(&hcl->conn));
		httpsrv_handle_http(hcl);
	}
}

/* This just polls sockets and puts them in the right active queue */
static void *
httpsrv_poller_thread(void *context) {
	httpsrv_t	*hs = (httpsrv_t *)context;
	int		r;

	logline(log_DEBUG_, "[d%" PRIu64 "] - start", hs->id);

	/* Handle the sockets in the global connset by polling them */
	while (thread_keep_running()) {
		/* logline(log_DEBUG_, "[d%" PRIu64 "]", hs->id); */
		r = connset_poll(&hs->connset);
		if (r < 0) {
			logline(log_NOTICE_, "connset_poll() failed %d", r);
			break;
		}
	}

	logline(log_DEBUG_, "[d%" PRIu64 "] exiting", hs->id);
	return (NULL);
}

void
httpsrv_silence(httpsrv_client_t *hcl) {
	logline(log_DEBUG_, "...");
	conn_events(&hcl->conn, CONN_POLLNONE);
	logline(log_DEBUG_, "end");
}

void
httpsrv_speak(httpsrv_client_t *hcl) {
	logline(log_DEBUG_, "...");
	conn_events(&hcl->conn, CONN_POLLIN | CONN_POLLOUT);
	logline(log_DEBUG_, "end");
}

/* These pull items off the active queue */
static void *
httpsrv_worker_thread(void *context) {
	httpsrv_t		*hs = (httpsrv_t *)context;
	conn_t			*conn;
	httpsrv_client_t	*hcl;

	logline(log_DEBUG_, "[d%" PRIu64 "] context", hs->id);

	while (thread_keep_running()) {

		/* Get some work to do */
		conn = connset_get_ready(&hs->connset);
		if (conn == NULL) {
			/*
			 * Error somewhere thus abort,
			 * stay quiet when shutting down
			 */
			if (thread_keep_running()) {
				logline(log_ERR_, " get_ready() failed...");
			}
			break;
		}

		thread_serve();

		hcl = conn_clientdata(conn);

		if (hcl == NULL) {
			/* Listen sockets don't have client data */
			logline(log_DEBUG_, CONN_ID " accept client...",
				conn_id(conn));
			httpsrv_accept(conn, hs);
		} else {
			logline(log_DEBUG_, CONN_ID " handle client",
				conn_id(&hcl->conn));

			/* Activity! */
			hcl->lastact = gettime();

			/* Receive incoming data */
			if (conn_poll_in(conn)) {
				httpsrv_receive(hcl, conn);
			}

			/* Output data to sockets that need it */
			if (conn_poll_out(conn)) {
				conn_flush(&hcl->conn);
			}

			/* Need to close it? */
			if (hcl->close) {
				logline(log_DEBUG_, CONN_ID " closing",
					conn_id(conn));
				list_remove_l(&hs->sessions, &hcl->node);
				httpsrv_client_close(hcl);
				conn = NULL;
			}
		}

		if (conn != NULL) {
			/* Processed the event */
			logline(log_DEBUG_, CONN_ID " processed",
				conn_id(conn));
			connset_handled_ready(conn);
		}
	}

	logline(log_DEBUG_, "exiting");

	return (NULL);
}

void
httpsrv_exit(httpsrv_t *hs) {
	httpsrv_client_t *hcl;

	assert(hs);
	assert(hs->id != 0);

	logline(log_DEBUG_, "[d%" PRIu64 "]", hs->id);

	/* Cleanup all open sessions */
	while ((hcl = (httpsrv_client_t *)list_pop(&hs->sessions))) {
		logline(log_DEBUG_, "closing [d%" PRIu64 "]" CONN_ID,
			hs->id, conn_id(&hcl->conn));
		httpsrv_client_close(hcl);
	}

	/* Cleanup all remaining connections */
	connset_destroy(&hs->connset);

	/* Empty her */
	memzero(hs, sizeof *hs);

	mfree(hs, sizeof *hs, "httpsrv_t");
}

bool
httpsrv_init(	httpsrv_t *hs,
		void *user,
		httpsrv_f f_accept,
		httpsrv_line_f f_header,
		httpsrv_f f_handle,
		httpsrv_f f_bodyfwddone,
		httpsrv_f f_done,
		httpsrv_f f_close)
{
	/* Unique connection number, for easy debugging */
	static unsigned int httpsrv_id = 0;

	/* Empty it all out */
	memzero(hs, sizeof *hs);

	/* New Id */
	hs->id = ++httpsrv_id;
	logline(log_DEBUG_, "[d%" PRIu64 "]", hs->id);

	/* Initialize the transaction & sessions list */
	list_init(&hs->sessions);

	/* Initialize the connections list */
	connset_init(&hs->connset);

	/* User provided options and callbacks */
	hs->user	= user;
	hs->accept	= f_accept;
	hs->header	= f_header;
	hs->handle	= f_handle;
	hs->bodyfwddone = f_bodyfwddone;
	hs->done	= f_done;
	hs->close	= f_close;

	return (true);
}

bool
httpsrv_start(httpsrv_t *hs, const char *hostname, unsigned int port, unsigned int numworkers) {
	unsigned int	i;

	/* Listen on the HTTP port (forwarded to from mod_hs) */
	if (!conn_create_listen(&hs->connset,
				hostname, IPPROTO_TCP, port)) {
		logline(log_CRIT_, "conn_create_listen()");
		return (false);
	}

	/* Launch a few HTTP worker threads */
	for (i = 0; i < numworkers; i++) {
		if (!thread_add("HTTPWorker", &httpsrv_worker_thread, hs)) {
			logline(log_CRIT_, "could not create thread");
			return (false);
		}
	}

	if (!thread_add("HTTPPoller", &httpsrv_poller_thread, hs)) {
		logline(log_CRIT_, "could not create thread");
		return (false);
	}

	return (true);
}

