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
	{ "<none>",	0 },
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
	fassert(HTTP_M_MAX == lengthof(http_methods));

	if (method >= lengthof(http_methods)) {
		log_crt( "Unknown HTTP method '%u'", method);
		return ("<UNKNOWN>");
	}

	return (http_methods[method].name);
}

void
httpsrv_set_userdata(httpsrv_client_t *hcl, void *user) {
	log_dbg(
		HCL_ID " " CONN_ID " %p",
		hcl->id, conn_id(&hcl->conn), user);
	hcl->user = user;
}

void *
httpsrv_get_userdata(httpsrv_client_t *hcl) {
	return (hcl->user);
}

void
httpsrv_set_posthandle_hook(conn_t UNUSED *conn, void *user);
void
httpsrv_set_posthandle_hook(conn_t UNUSED *conn, void *user) {
	httpsrv_client_t *hcl = (httpsrv_client_t *)user;

	hcl->posthandle(hcl);
}

void
httpsrv_set_posthandle(httpsrv_client_t *hcl, httpsrv_sf f) {
	hcl->posthandle = f;
	conn_set_posthandle(&hcl->conn, httpsrv_set_posthandle_hook, hcl);
}

void
httpsrv_close(httpsrv_client_t *hcl) {
	log_dbg(
		HCL_ID " " CONN_ID,
		hcl->id, conn_id(&hcl->conn));
	hcl->close = true;
}

void
httpsrv_client_destroy(httpsrv_client_t *hcl) {
	/* Destroy the connection */
	conn_destroy(&hcl->conn);

	/* Cleanup the headers */
	buf_destroy(&hcl->the_headers);

	mfree(hcl, sizeof *hcl, "httpsrv_client_t");
}

bool
httpsrv_client_close(httpsrv_client_t *hcl, bool force);
bool
httpsrv_client_close(httpsrv_client_t *hcl, bool force) {
	log_dbg(
		HCL_ID ", " CONN_ID " Closing session",
		hcl->id, conn_id(&hcl->conn));

	/* Flush & Close the connections */
	if (conn_is_there(&hcl->conn)) {
		conn_flush(&hcl->conn);

		if (!force && conn_flushleft(&hcl->conn) > 0) {
			log_dbg(
				HCL_ID ", " CONN_ID " Can't close "
				"still need to flush more",
				hcl->id, conn_id(&hcl->conn));
			return (false);
		}

	}

	if (hcl->hs->close)
		hcl->hs->close(hcl, hcl->user);

	/* Destroy it */
	httpsrv_client_destroy(hcl);
	return (true);
}

static void
httpsrv_http_headertime(httpsrv_client_t *hcl, const char *header, time_t t);
static void
httpsrv_http_headertime(httpsrv_client_t *hcl, const char *header, time_t t) {
	static const char days[7][4] =
			{ "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
	static const char mons[12][4] =
			{ "Jan", "Feb", "Mar", "Apr", "May", "Jun",
			  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct tm	tm;

	gmtime_r(&t, &tm);

	conn_addheaderf(&hcl->conn,
			"%s: %s, %u %s %u %u:%u:%u GMT",
			header,
			days[tm.tm_wday],
			tm.tm_mday,
			mons[tm.tm_mon],
			tm.tm_year + 1900,
			tm.tm_hour,
			tm.tm_min,
			tm.tm_sec);
}

void
httpsrv_expire(httpsrv_client_t *hcl, unsigned int maxage) {
	time_t		t;

	t = time(NULL);

	if (maxage == 0)
	{
		/* Always force expire this URI / do not cache */

		/* Always modified */
		httpsrv_http_headertime(hcl, "Last-Modified", t);

		/*
		 * Date in the far past
		 * (over 9M hits on google for this string :)
		 */
		conn_addheader(&hcl->conn,
				"Expires: Thu, 29 Oct 1998 17:04:19 GMT");

		/* HTTP/1.1 style */
		conn_addheader(&hcl->conn,
				"Cache-Control: public, no-cache, "
				"no-store, must-revalidate");
	}
	else
	{
		/* Do not expire this for another maxage seconds */

		/* Last modified some time ago */
		httpsrv_http_headertime(hcl, "Last-Modified", t);

		/* Expires in the future */
		httpsrv_http_headertime(hcl, "Expires", t + maxage);

		/* HTTP/1.1 style */
		conn_addheaderf(&hcl->conn,
				"Cache-Control: max-age=%u",
				maxage);
	}
}

void
httpsrv_answer(httpsrv_client_t *hcl, unsigned int code, const char *msg, const char *ctype) {
	conn_addheaderf(&hcl->conn, "HTTP/1.1 %u %s", code, msg);

	if (code != 200) {
		log_err(
			HCL_ID " " CONN_ID " HTTP Error %u %s",
			hcl->id, conn_id(&hcl->conn), code, msg);
	}

	if (ctype != NULL) {
		conn_addheaderf(&hcl->conn, "Content-Type: %s", ctype);
	}
}

void
httpsrv_error(httpsrv_client_t *hcl, unsigned int code, const char *msg) {
	httpsrv_answer(hcl, code, msg, HTTPSRV_CTYPE_HTML);

	if (hcl->hs->top)
		hcl->hs->top(hcl, hcl->user);

	conn_printf(
		&hcl->conn,
		"<h1>Error %u</h1>\n"
		"<p>\n"
		"%s."
		"</p>\n",
		code, msg);

	if (hcl->hs->tail)
		hcl->hs->tail(hcl, hcl->user);
}

static bool
httpsrv_handle_http_skipbody(httpsrv_client_t *hcl);
static bool
httpsrv_handle_http_skipbody(httpsrv_client_t *hcl) {
	uint64_t	len;
	int		i;

	log_dbg(
		HCL_ID " " CONN_ID " SkipBody l:%" PRIu64,
		hcl->id, conn_id(&hcl->conn), hcl->skipbody_len);

	/* How much do we have? */
	len = conn_buffer_cur(&hcl->conn);

	if (len == 0) {
		/* Try to get more */
		i = conn_recv(&hcl->conn);
		if (i == 0) {
			/* Try at another time */
			return (true);
		}

		/* We got some more, try again */
		return (false);
	}

	/* Only skip over what needs to be skipped */
	if (len > hcl->skipbody_len) {
		len = hcl->skipbody_len;
	}

	/* Skip it */
	conn_buffer_shift(&hcl->conn, len);

	hcl->skipbody_len -= len;

	log_dbg(
		HCL_ID " " CONN_ID " SkipBody l:%" PRIu64 " d:%" PRIu64,
		hcl->id, conn_id(&hcl->conn), hcl->skipbody_len, len);

	/* Try some more */
	return (false);
}

static bool
httpsrv_handle_http_bodyfwd(httpsrv_client_t *hcl);
static bool
httpsrv_handle_http_bodyfwd(httpsrv_client_t *hcl) {
	uint64_t	len;
	int		i;

	log_dbg(
		HCL_ID " " CONN_ID " -> " HCL_ID " " CONN_ID
		" BodyFwd",
		hcl->id,
		conn_id(&hcl->conn),
		hcl->bodyfwd->id,
		conn_id(&hcl->bodyfwd->conn));

	/* Copy some more */
	len = conn_copym(&hcl->conn,
			&hcl->bodyfwd->conn,
			hcl->bodyfwd_len);

	log_dbg(
		HCL_ID " " CONN_ID " -> " HCL_ID " " CONN_ID
		" BodyFwd %" PRIu64,
		hcl->id,
		conn_id(&hcl->conn),
		hcl->bodyfwd->id,
		conn_id(&hcl->bodyfwd->conn),
		len);

	if (len == 0) {
		/* Try to get more */
		i = conn_recv(&hcl->conn);
		if (i == 0) {
			/* Try at another time */
			return (true);
		}

		/* We got some more */
		return (false);
	}

	/* Some bits less */
	fassert(len <= hcl->bodyfwd_len);
	hcl->bodyfwd_len -= len;

	/*
	 * Allow partial body content reads
	 * by keeping track of what is left of the body
	 */
	fassert(len <= hcl->headers.content_length);
	hcl->headers.content_length -= len;

	/* Done or something went wrong? */
	if (hcl->bodyfwd_len == 0 || len == 0) {

		log_dbg(
			HCL_ID " " CONN_ID " -> " HCL_ID " " CONN_ID
			" BodyFwd Done",
			hcl->id,
			conn_id(&hcl->conn),
			hcl->bodyfwd->id,
			conn_id(&hcl->bodyfwd->conn));

		/* Inform the caller */
		fassert(hcl->hs->bodyfwd_done != NULL);
		hcl->hs->bodyfwd_done(hcl, hcl->bodyfwd, hcl->user);

		fassert(hcl->bodyfwd != NULL);

		log_dbg(
			HCL_ID " " CONN_ID "->" CONN_ID " BodyFwd Flush",
			hcl->id,
			conn_id(&hcl->conn),
			conn_id(&hcl->bodyfwd->conn));

		httpsrv_done(hcl->bodyfwd);
		connset_handling_done(&hcl->bodyfwd->conn, false);

		/* Handled it */
		hcl->bodyfwd = NULL;
		hcl->bodyfwd_len = 0;

		/* Done with this for now */
		httpsrv_done(hcl);
		return (true);
	}

	return (false);
}

static bool
httpsrv_handle_http_readbody(httpsrv_client_t *hcl);
static bool
httpsrv_handle_http_readbody(httpsrv_client_t *hcl) {
	uint64_t	len;
	int		i;
	bool		done;

	len = conn_buffer_cur(&hcl->conn);

	if (len == 0) {
		/* Try to get more */
		i = conn_recv(&hcl->conn);
		if (i == 0) {
			/* Try at another time */
			return (true);
		}

		/* We got some more */
		return (false);
	}

	/* Only read upto the max even if there is more */
	if (len > hcl->readbody_len) {
		len = hcl->readbody_len;
	}

	log_dbg(
		HCL_ID " " CONN_ID " ReadBody "
		"%" PRIu64 " / %" PRIu64 " / %" PRIu64,
		hcl->id,
		conn_id(&hcl->conn),
		len,
		hcl->readbody_len,
		hcl->readbody_off);

	/* Copy it to the user supplied buffer */
	memcpy(	&hcl->readbody[hcl->readbody_off],
		conn_buffer(&hcl->conn),
		len);

	/* We read this from the buffer */
	conn_buffer_shift(&hcl->conn, len);

	/* Some more gone, some more there */
	hcl->readbody_len -= len;
	hcl->readbody_off += len;

	/*
	 * Allow partial body content reads
	 * by keeping track of what is left of the body
	 */
	fassert(len <= hcl->headers.content_length);
	hcl->headers.content_length -= len;

	/* Complete? Call handle function */
	if (hcl->readbody_len == 0) {
		/* Process it */
		fassert(hcl->hs->handle);

		log_dbg(
			HCL_ID " handling body",
			hcl->id);

		done = hcl->hs->handle(hcl, hcl->user);

		log_dbg(
			HCL_ID " handling body complete (done:%s)",
			hcl->id, yesno(done));

		if (done) {
			return (true);
		}
	}

	return (false);
}

static void
httpsrv_handle_http(httpsrv_client_t *hcl);
static void
httpsrv_handle_http(httpsrv_client_t *hcl) {
	char		line[4096];
	int		i;
	unsigned int	l, m;
	uint32_t	t32;
	uint64_t	t64, len;
	bool		done;

	log_dbg(
		HCL_ID " " CONN_ID ", "
		"skip: %" PRIu64 ", "
		"fwdb:%" PRIu64 ", "
		"read:%" PRIu64,
		hcl->id, conn_id(&hcl->conn),
		hcl->skipbody_len,
		hcl->bodyfwd_len,
		hcl->readbody_len);

	/* As long as we got lines parse them */
	while (true) {
		/* Skip over the body? */
		if (hcl->skipbody_len) {
			if (httpsrv_handle_http_skipbody(hcl))
				return;
			continue;
		}

		/* Forwarding the body? */
		if (hcl->bodyfwd) {
			if (httpsrv_handle_http_bodyfwd(hcl))
				return;
			continue;
		}

		/* Read in the buffer? */
		if (hcl->readbody) {
			if (httpsrv_handle_http_readbody(hcl))
				return;
			continue;
		}

		/* There should be something in this buffer */
		i = conn_recvline(&hcl->conn, line, sizeof line);
		if (i == -EINVAL) {
			httpsrv_error(hcl, 400,
				      "ASCII NUL character found in stream");

			log_err(
				HCL_ID " ASCII NULL found, closing",
				hcl->id);

			/* Close it up */
			httpsrv_close(hcl);
			return;

		} else if (i < 0) {
			log_err(
				HCL_ID " Receive line problem (%d), closing",
				hcl->id, i);

			/* Close it up */
			httpsrv_close(hcl);
			return;

		} else if (i == 0) {
			log_dbg(
				HCL_ID " " CONN_ID " No new line yet",
				hcl->id,
				conn_id(&hcl->conn));

			/* Dump what we got */
			len = conn_buffer_cur(&hcl->conn);
			if (len > 0) {
				dumppacket(LOG_DEBUG,
					 (uint8_t *)conn_buffer(&hcl->conn),
					 len);
			}

			/* Nothing left */
			return;
		}

		l = i;

		/* Empty line == end of command */
		if (l == 1 && line[0] == '\n') {
			log_dbg(
				HCL_ID " Got an empty line",
				hcl->id);

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
				log_dbg(
					HCL_ID " No Local Port found",
					hcl->id);
			}

			if (sscanf(hcl->headers.remote_port_s, "%u", &t32) == 1 &&
				t32 != 0) {
				hcl->headers.remote_port = t32;
			} else {
				log_dbg(
					HCL_ID " No Remote Port found",
					hcl->id);
			}

			/* Post? Requires a content-length */
			if (hcl->method == HTTP_M_POST) {
				if (sscanf(hcl->headers.content_length_s,
					   "%" PRIu64, &t64) == 1) {
					hcl->headers.content_length = t64;
				} else {
					log_wrn(
						HCL_ID
						" POST without Content-Length",
						hcl->id);

					httpsrv_error(hcl, 400,
						"POST without Content-Length");
					httpsrv_close(hcl);
				}
			}

			/* Another request fed in */
			hcl->reqid++;

			/* Process it */
			fassert(hcl->hs->handle);

			log_dbg(
				HCL_ID " handling",
				hcl->id);

			done = hcl->hs->handle(hcl, hcl->user);

			log_dbg(
				HCL_ID " handling complete (done: %s)",
				hcl->id, yesno(done));

			/* Next */
			if (done)
				return;
			else
				continue;
		}

		/* Remove trailing \n */
		line[--l] = '\0';

		log_dbg(
			HCL_ID" got line (len=%u) : %s",
			hcl->id, l, line);

		/* No method yet? */
		if (hcl->method == HTTP_M_NONE) {
			for (m = 1; m < lengthof(http_methods); m++) {
				if (strncasecmp(line, http_methods[m].name,
						http_methods[m].len) != 0 ||
				    line[http_methods[m].len] != ' ') {
					continue;
				}

				hcl->method = m;
				break;
			}

			if (hcl->method == HTTP_M_NONE) {
				log_ntc(
					HCL_ID " Unknown HTTP: %s",
					hcl->id, line);

				httpsrv_error(hcl, 501, "Not Implemented");
				httpsrv_close(hcl);
				return;
			}

			if (l >= sizeof hcl->the_request) {
				log_ntc(
					HCL_ID " Request Too Big: %s",
					hcl->id, line);

				httpsrv_error(hcl, 414, "Request-URI Too Long");
				httpsrv_close(hcl);
				return;
			}

			/* Store the request for later parsing */
			memcpy(hcl->the_request, line, l);
			hcl->the_request[l] = '\0';
			continue;
		}

		/* Add headers to the raw headers */
		buf_lock(&hcl->the_headers);
		buf_putl(&hcl->the_headers, line, l);
		buf_putl(&hcl->the_headers, "\r\n", 2);
		buf_unlock(&hcl->the_headers);

		/* Parse the header line */
		misc_map(line, httpsrv_headers, (char *)&hcl->headers);

		/* Does the caller want headers? */
		if (hcl->hs->header)
			hcl->hs->header(hcl, hcl->user, line);
	}
}

void
httpsrv_done(httpsrv_client_t *hcl) {
	fassert(hcl->keephandling == false);

	/* Skip remaining content_length */
	hcl->skipbody_len = hcl->headers.content_length;
	hcl->headers.content_length = 0;

	log_dbg(
		HCL_ID " " CONN_ID " is done (%s), "
		"remainder %" PRIu64,
		hcl->id, conn_id(&hcl->conn),
		httpsrv_methodname(hcl->method),
		hcl->skipbody_len);

	/* Clean up read body */
	httpsrv_readbody_free(hcl);

	/* Call the client's done function */
	if (hcl->hs->done)
		hcl->hs->done(hcl, hcl->user);

	/*
	 * Flush the output buffer
	 * We do not care if the flush is complete,
	 * that will happen in the livetime of it
	 */
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
	buf_emptyL(&hcl->the_headers);

	/* No arguments yet either */
	hcl->headers.argc = 0;

	/* Reset */
	hcl->close = false;
	hcl->keephandling = false;

	/* Should be clean before landing here */
	fassert(hcl->bodyfwd == NULL && hcl->bodyfwd_len == 0);

	/*
	 * This cl connection is now ready for the next request
	 * which could be in the buffer already due to HTTP pipelining
	 *
	 * Thus try to parse more lines if there are more already
	 */
	if (!(conn_buffer_isempty(&hcl->conn))) {
		log_dbg(
			HCL_ID " " CONN_ID " has data in receive buffer",
			hcl->id, conn_id(&hcl->conn));

		httpsrv_handle_http(hcl);
	} else {
		log_dbg(
			HCL_ID " " CONN_ID " has nothing queued",
			hcl->id, conn_id(&hcl->conn));
	}

	log_dbg(
		HCL_ID " " CONN_ID " re-enabling events",
		hcl->id, conn_id(&hcl->conn));

	/* Tell it to try to output (flush) */
	conn_events(&hcl->conn, CONN_POLLIN | CONN_POLLOUT);

	log_dbg(
		HCL_ID " " CONN_ID " end",
		hcl->id, conn_id(&hcl->conn));
}

bool
httpsrv_parse_request(httpsrv_client_t *hcl) {
	unsigned int	j, ro = 0, ao = 0, uo = 0;
	char		c, *s, *h;
	const char	*line;
	bool		isarg = false;
	uint32_t	proto;

	/* Only parse it once */
	if (hcl->headers.args[0] != '\0') {
		log_dbg(
			HCL_ID " " CONN_ID " Not parsing again",
			hcl->id, conn_id(&hcl->conn));
		return (true);
	}

	line = hcl->the_request;

	log_dbg(
		HCL_ID " " CONN_ID " scanning: %s",
		hcl->id, conn_id(&hcl->conn), line);

	fassert(sizeof hcl->headers.argsplit == sizeof hcl->headers.args);

	/* Nothing found yet */
	hcl->headers.argc = 0;
	memzero(hcl->headers.argi, sizeof hcl->headers.argi);
	hcl->headers.argi[0].var = hcl->headers.argsplit;

	/* First skip over the method */
	for (j = 0; line[j] != ' '; j++);

	/* Skip over the space behind the method */
	j++;

	for (	;
		ro < (sizeof hcl->headers.rawuri - 1) &&
		uo < (sizeof hcl->headers.uri    - 1) &&
		ao < (sizeof hcl->headers.args   - 1);
		j++) {

		fassert(hcl->headers.argc < lengthof(hcl->headers.argi));

		c = line[j];

		/* Keep a Raw URI */
		hcl->headers.rawuri[ro++] = c;

		if (c == ' ' || c == '\0') {
			/* Was the last argument used at least a bit? */
			if (strlen(
				hcl->headers.argi[hcl->headers.argc].var) > 0)
				hcl->headers.argc++;
				if (hcl->headers.argc >=
					lengthof(hcl->headers.argi)) {
					log_ntc(
						HCL_ID " " CONN_ID " Too many args",
						hcl->id, conn_id(&hcl->conn));
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
				log_ntc(
					HCL_ID " " CONN_ID " Broken URL: %s",
					hcl->id, conn_id(&hcl->conn), line);
				httpsrv_error(hcl, 400, "Wrongly encoded URL");
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

			/* Skip over the '%' */
			j++;

			/* Copy over the unmangled variant */
			hcl->headers.rawuri[ro++] = line[j++];
			hcl->headers.rawuri[ro++] = line[j];

			/* The for() while do the j++ for this char */
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
					log_ntc(
						HCL_ID " " CONN_ID "Too many args",
						hcl->id, conn_id(&hcl->conn));
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

	/* Just in case */
	assert(ro < (sizeof hcl->headers.rawuri - 1));
	assert(uo < (sizeof hcl->headers.uri    - 1));
	assert(ao < (sizeof hcl->headers.args   - 1));

	/* Get the local + remote IP/port */
	conn_getinfo(
		&hcl->conn, true,
		hcl->headers.local_ip,
		sizeof hcl->headers.local_ip,
		&proto, &hcl->headers.local_port);

	conn_getinfo(
		&hcl->conn, false,
		hcl->headers.remote_ip,
		sizeof hcl->headers.remote_ip,
		&proto, &hcl->headers.remote_port);

	/* Not starting with a slash, possibly a proxied request */
	if (hcl->headers.uri[0] != '/') {
		/* Strip http/https proxied URLs */
		if (strncasecmp(hcl->headers.uri, "http://", 7) == 0 ||
		    strncasecmp(hcl->headers.uri, "https://", 8) == 0) {
			log_dbg(
				HCL_ID " " CONN_ID " Proxied Request: %s",
				hcl->id, conn_id(&hcl->conn),
				hcl->headers.uri);

			/* Find the end of the hostname */
			h = hcl->headers.uri;
			h = strchr(h, '/');
			h = strchr(h+1, '/');
			s = strchr(h+1, '/');
			if (s == NULL) {
				log_ntc(
					HCL_ID " " CONN_ID
					" Broken Proxy URL: %s",
					hcl->id, conn_id(&hcl->conn),
					hcl->headers.uri);
				httpsrv_error(hcl, 400, "Broken Proxy URL");
				return (false);
			}

			/* The hostname */
			strncpy(hcl->headers.hostname,
				h+1, (s - h) - 1);

			/* Move the real URI to the start */
			memmove(hcl->headers.uri, s,
				sizeof(hcl->headers.uri) -
					(s - hcl->headers.uri));
		} else {
			log_ntc(
				HCL_ID " " CONN_ID
				" Broken URL: %s",
				hcl->id, conn_id(&hcl->conn),
				hcl->headers.uri);
			httpsrv_error(hcl, 400, "URL without root");
			return (false);
		}
	}

	/* Note that this client hit us */
	log_dbg(
		HCL_ID " " CONN_ID "\n"
		"HTTP: the_request: %s (%u)\n"
		"HTTP: hostname: %s\n"
		"HTTP: uri: %s\n"
		"HTTP: local: %s/%u\n"
		"HTTP: remote: %s/%u",
		hcl->id,
		conn_id(&hcl->conn),
		hcl->the_request, (unsigned int)strlen(hcl->the_request),
		hcl->headers.hostname,
		hcl->headers.uri,
		hcl->headers.local_ip, hcl->headers.local_port,
		hcl->headers.remote_ip, hcl->headers.remote_port);

	log_dbg(
		HCL_ID " " CONN_ID " Got %u arguments:",
		hcl->id, conn_id(&hcl->conn), hcl->headers.argc);

	for (j = 0; j < hcl->headers.argc; j++) {
		log_dbg(
			HCL_ID " " CONN_ID " Arg %u :: %s = %s",
			hcl->id,
			conn_id(&hcl->conn),
			j,
			hcl->headers.argi[j].var,
			hcl->headers.argi[j].val);
	}

	log_dbg(
		HCL_ID " " CONN_ID " args = %s",
		hcl->id, conn_id(&hcl->conn), hcl->headers.args);

	if (strlen(hcl->headers.hostname) == 0) {
		httpsrv_error(hcl, 400, "Bad Request - missing or empty Host header");
		return (false);
	}

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

httpsrv_client_t *
httpsrv_newcl(httpsrv_t *hs) {
	/* Unique number, for easy debugging */
	static uint64_t		cl_id = 0;
	httpsrv_client_t	*hcl;
	bool			r;

	mutex_lock(hs->mutex);

	log_dbg( "[hs%" PRIu64 "]", hs->id);

	/* Create a cl session */
	hcl = mcalloc(sizeof *hcl, "httpsrv_client_t");
	if (hcl == NULL) {
		log_crt( "[hs%" PRIu64 "] alloc failed", hs->id);
		mutex_unlock(hs->mutex);
		return (NULL);
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
		log_err(
			HCL_ID " Could not init connection",
			hcl->id);

		r = httpsrv_client_close(hcl, true);
		if (!r) {
			log_err( "Could not close new HCL (conn)");
		}

		mutex_unlock(hs->mutex);
		return (NULL);
	}

	/* Init the buffers */
	if (!buf_init(&hcl->the_headers)) {
		log_err(
			HCL_ID " Could not init buf",
			hcl->id);

		r = httpsrv_client_close(hcl, true);
		if (!r) {
			log_err( "Could not close new HCL (buf)");
		}

		mutex_unlock(hs->mutex);
		return (NULL);
	}

	mutex_unlock(hs->mutex);

	return (hcl);
}

/* Accept incoming client connections */
static void
httpsrv_accept(conn_t *lconn, httpsrv_t *hs) {
	httpsrv_client_t	*hcl;
	bool			r;

	log_dbg(
		"[hs%" PRIu64 "] l:" CONN_ID,
		hs->id, conn_id(lconn));

	hcl = httpsrv_newcl(hs);

	/* Accept the socket */
	if (!conn_accept(&hcl->conn, lconn, hcl)) {
		log_ntc(
			HCL_ID " l:" CONN_ID " conn_accept()",
			hcl->id, conn_id(lconn));

		r = httpsrv_client_close(hcl, true);
		if (!r) {
			log_ntc(
				HCL_ID " l:" CONN_ID
				" Could not close HCL on accept",
				hcl->id, conn_id(lconn));
		}
		return;
	}

	log_dbg(
		HCL_ID " l:" CONN_ID " accepted " CONN_ID,
		hcl->id, conn_id(lconn), conn_id(&hcl->conn));

	/* Register this session in our sessions list */
	list_addtail_l(&hs->sessions, &hcl->node);

	/* User supplied function */
	if (hcl->hs->accept)
		hcl->hs->accept(hcl, hcl->hs->user);

	/* We expect to receive something from it */
	conn_events(&hcl->conn, CONN_POLLIN);

	return;
}

/* Receive hcl commands */
static void
httpsrv_receive(httpsrv_client_t *hcl, conn_t *conn) {
	int i;

	log_dbg(
		HCL_ID " " CONN_ID,
		hcl->id, conn_id(&hcl->conn));

	/* This is a non-blocking socket thus receive a bit */
	i = conn_recv(conn);
	if (i == 0) {
		log_dbg(
			HCL_ID " " CONN_ID " nothing more",
			hcl->id, conn_id(&hcl->conn));
	} else if (i < 0) {
		log_dbg(
			HCL_ID " " CONN_ID " Remote closed connection (%d)",
			hcl->id, conn_id(&hcl->conn), i);

		/* It is broken, nothing else to do with it*/
		conn_events(&hcl->conn, CONN_POLLNONE);

		/* Close the connection, it is gone */
		conn_close(conn);

		/* Mark it for closing */
		httpsrv_close(hcl);
	} else {
		/* HTTP Connection */
		log_dbg(
			HCL_ID " " CONN_ID " Try to parse some lines",
			hcl->id, conn_id(&hcl->conn));
		httpsrv_handle_http(hcl);
	}

	log_dbg(
		HCL_ID " " CONN_ID " done",
		hcl->id, conn_id(&hcl->conn));
}

/* This just polls sockets and puts them in the right active queue */
static void *
httpsrv_poller_thread(void *context) {
	httpsrv_t	*hs = (httpsrv_t *)context;
	int		r;

	log_dbg( "[hs%" PRIu64 "] - start", hs->id);

	/* Handle the sockets in the global connset by polling them */
	while (thread_keep_running()) {
		/* log_dbg( "[hs%" PRIu64 "]", hs->id); */
		r = connset_poll(&hs->connset);
		if (r < 0) {
			log_ntc(
				"[hs%" PRIu64 "] connset_poll() failed %d",
				hs->id, r);
			break;
		}
	}

	log_dbg( "[hs%" PRIu64 "] exiting", hs->id);
	return (NULL);
}

/* Very crude, but calling 'file --mime-type' is a bit much */
static const char *
httpsrv_mimetype(const char *file);
static const char *
httpsrv_mimetype(const char *file) {
	const char	*mime = HTTPSRV_CTYPE_BINARY;
	const char	*ext;
	unsigned int	i, l;

	/* Find the last dot (.) */
	l = strlen(file);
	for (i = l; i > 0 && file[i] != '.'; i--);

	/* No extension? */
	if (l == i) {
		log_dbg( "%s has no extension?", file);
		return (mime);
	}

	ext = &file[i+1];

	log_dbg( "%s has extension: %s", file, ext);

	/* Compare the extension */
	if (strcmp(ext, "css") == 0)
		mime = HTTPSRV_CTYPE_CSS;
	else if (strcmp(ext, "html") == 0)
		mime = HTTPSRV_CTYPE_HTML;
	else if (strcmp(ext, "json") == 0)
		mime = HTTPSRV_CTYPE_JSON;
	else if (strcmp(ext, "jpg") == 0)
		mime = HTTPSRV_CTYPE_JPEG;
	else if (strcmp(ext, "jpeg") == 0)
		mime = HTTPSRV_CTYPE_JPEG;
	else if (strcmp(ext, "png") == 0)
		mime = HTTPSRV_CTYPE_PNG;

	log_dbg( "%s has mime-type: %s", file, mime);

	return (mime);
}

void
httpsrv_sendfile(httpsrv_client_t *hcl, const char *file) {
	const char *mime;

	if (!conn_sendfile(&hcl->conn, file)) {
		httpsrv_error(hcl, 404, "Not Found");
		return;
	}

	/* Get the mime type */
	mime = httpsrv_mimetype(file);

	/* Answer it */
	httpsrv_answer(hcl, HTTPSRV_HTTP_OK, mime);
}

void
httpsrv_forward(httpsrv_client_t *hin, httpsrv_client_t *hout) {
	log_dbg(
		HCL_ID " to " HCL_ID " %" PRIu64 " bytes",
		hin->id, hout->id, hin->headers.content_length);

	/* Make sure there is content to forward */
	fassert(hin->headers.content_length != 0);

	/* Make it forward the body from hin to hout */
	hin->bodyfwd = hout;
	hin->bodyfwd_len = hin->headers.content_length;

	/* Directly suck the existing buffer empty */
	httpsrv_handle_http(hin);

	log_dbg(
		HCL_ID " to " HCL_ID " (done)",
		hin->id, hout->id);
}

/* These pull items off the active queue */
static void *
httpsrv_worker_thread(void *context) {
	httpsrv_t		*hs = (httpsrv_t *)context;
	conn_t			*conn;
	httpsrv_client_t	*hcl;
	bool			k;

	log_dbg( "[hs%" PRIu64 "] context", hs->id);

	while (thread_keep_running()) {

		/* Get some work to do */
		conn = connset_get_ready(&hs->connset);
		if (conn == NULL) {
			/*
			 * Error somewhere thus abort,
			 * stay quiet when shutting down
			 */
			if (thread_keep_running()) {
				log_err(
					"[hs%" PRIu64 "] failed...",
					hs->id);
			}
			break;
		}

		thread_serve();

		hcl = conn_clientdata(conn);

		if (hcl == NULL) {
			/* Listen sockets don't have client data */
			log_dbg(
				CONN_ID " accept client...",
				conn_id(conn));
			httpsrv_accept(conn, hs);
		} else {
			log_dbg(
				HCL_ID " " CONN_ID " handle client",
				hcl->id, conn_id(&hcl->conn));

			/* Activity! */
			hcl->lastact = gettime();

			/* Receive incoming data */
			if (conn_poll_in(conn)) {
				log_dbg(
					HCL_ID " " CONN_ID " receiving",
					hcl->id, conn_id(&hcl->conn));
				httpsrv_receive(hcl, conn);
			}

			/* Output data to sockets that need it */
			if (conn_poll_out(conn)) {
				log_dbg(
					HCL_ID " " CONN_ID " flushing",
					hcl->id, conn_id(&hcl->conn));
				conn_flush(&hcl->conn);
			}

			/* Need to close it? */
			if (hcl->close) {
				log_dbg(
					HCL_ID " " CONN_ID " was closed",
					hcl->id, conn_id(conn));

				/*
				 * Don't do anything with this anymore
				 * Might be closed already here
				 */
				if (conn_is_valid(&hcl->conn)) {
					conn_events(&hcl->conn, CONN_POLLNONE);
				}

				/* Handling needs to be done */
				fassert(hcl->keephandling == false);
				connset_handling_done(conn, false);

				/* Remove the item from the list */
				list_remove_l(&hs->sessions, &hcl->node);

				if (httpsrv_client_close(hcl, false)) {
					/* It really is gone */
				} else {
					/* It should go later */
					log_dbg(
						HCL_ID " " CONN_ID
						" Closing delayed for flush",
						hcl->id, conn_id(conn));

					/* Not gone, add it back */
					list_addtail_l(&hs->sessions, &hcl->node);
				}

				/* Already done handled_ready */
				conn = NULL;
			}
		}

		if (conn != NULL) {
			if (hcl) {
				k = hcl->keephandling;
				hcl->keephandling = false;
			} else {
				k = false;
			}

			/* Processed the event */
			log_dbg(
				CONN_ID " processed (keephandling=%s,new=%s)",
				conn_id(conn),
				hcl != NULL ? yesno(k) : "nohcl",
				hcl != NULL ? yesno(hcl->keephandling) : "nohcl");

			connset_handling_done(conn, k);
		}
	}

	log_dbg( "exiting");

	return (NULL);
}

int
httpsrv_readbody_alloc(httpsrv_client_t *hcl, uint64_t min, uint64_t max) {
	uint64_t size = hcl->headers.content_length;

	/* Should never try to read a 0 length body */
	fassert(size != 0);

	/* If no maximum given, default to 5 MiB */
	if (max == 0) {
		max = 5*1024*1024;
	}

	if (size < min) {
		httpsrv_error(hcl, 500, "POST body too puny");
		return (-ENOSPC);
	}

	if (size > max) {
		httpsrv_error(hcl, 500, "POST body too big");
		return (-EFBIG);
	}

	/*
	 * Add an extra byte for an ASCII NUL char so that we can
	 * treat the whole thing as a string if needed
	 */
	size += 1;

	log_dbg(
		"Allocating %" PRIu64 " bytes for the body",
		hcl->headers.content_length);

	/* Let the HTTP engine read the body in here */
	hcl->readbody = mcalloc(size, "HTTPBODY");
	if (hcl->readbody == NULL) {
		httpsrv_error(hcl, 500, "Out of Memory");
		return (-ENOMEM);
	}

	/* Actual length of the body that we want to read */
	hcl->readbody_len = hcl->headers.content_length;
	hcl->readbody_off = 0;

	/* Buffer Length */
	hcl->readbody_siz = size;

	return (0);
}

void
httpsrv_readbody_free(httpsrv_client_t *hcl) {
	log_dbg(
		HCL_ID " readbody = %p, %" PRIu64,
		hcl->id,
		(void *)hcl->readbody,
		hcl->readbody_siz);

	if (hcl->readbody) {
		mfree(hcl->readbody, hcl->readbody_siz, "HTTPBODY");

		hcl->readbody = NULL;
		hcl->readbody_len = 0;
		hcl->readbody_off = 0;
		hcl->readbody_siz = 0;
	}
}

void
httpsrv_sessions(httpsrv_client_t *hcl) {
	httpsrv_client_t *h, *hn;
	unsigned int	cnt = 0;

	list_lock(&hcl->hs->sessions);
	list_for(&hcl->hs->sessions, h, hn, httpsrv_client_t *) {
		if (cnt == 0) {
			conn_put(&hcl->conn,
				"<table>\n"
				"<tr>\n"
				"<th>ID</th>\n"
				"<th>ReqID</th>\n"
				"<th>Local_IP</th>\n"
				"<th>Local_Port</th>\n"
				"<th>Remote_IP</th>\n"
				"<th>Remote_Port</th>\n"
				"<th>Hostname</th>\n"
				"<th>Request</th>\n"
				"</tr>\n");
		}

		conn_printf(&hcl->conn,
			    "<tr>"
			    "<td>" HCL_ID "</td>"
			    "<td>%" PRIu64 "</td>"
			    "<td>%s</td>"
			    "<td>%u</td>"
			    "<td>%s</td>"
			    "<td>%u</td>"
			    "<td>%s</td>"
			    "<td>%s</td>"
			    "<tr>\n",
			    h->id,
			    h->reqid,
			    h->headers.local_ip,
			    h->headers.local_port,
			    h->headers.remote_ip,
			    h->headers.remote_port,
			    h->headers.hostname,
			    h->the_request);
		cnt++;
	}
	list_unlock(&hcl->hs->sessions);

	if (cnt == 0) {
		conn_put(&hcl->conn,
			"No active sessions");
	} else {
		conn_put(&hcl->conn,
			"</table>\n");
	}
}

void
httpsrv_exit(httpsrv_t *hs) {
	httpsrv_client_t *hcl;

	fassert(hs);
	fassert(hs->id != 0);

	log_dbg( "[hs%" PRIu64 "]", hs->id);

	/* Cleanup all open sessions */
	while ((hcl = (httpsrv_client_t *)list_pop(&hs->sessions))) {
		log_dbg( HCL_ID " " CONN_ID " exiting",
			hcl->id, conn_id(&hcl->conn));
		httpsrv_client_close(hcl, true);
	}

	/* Cleanup all remaining connections */
	connset_destroy(&hs->connset);

	/* Destroy it */
	mutex_destroy(hs->mutex);

	/* Empty her */
	memzero(hs, sizeof *hs);

	mfree(hs, sizeof *hs, "httpsrv_t");
}

bool
httpsrv_init(	httpsrv_t *hs,
		void *user,
		httpsrv_f f_top,
		httpsrv_f f_tail,
		httpsrv_f f_accept,
		httpsrv_line_f f_header,
		httpsrv_done_f f_handle,
		httpsrv_bfwd_f f_bodyfwd_done,
		httpsrv_f f_done,
		httpsrv_f f_close)
{
	/* Unique connection number, for easy debugging */
	static unsigned int httpsrv_id = 0;

	/* Empty it all out */
	memzero(hs, sizeof *hs);

	/* New Id */
	hs->id = ++httpsrv_id;
	log_dbg( "[hs%" PRIu64 "]", hs->id);

	/* The lock */
	mutex_init(hs->mutex);

	/* Initialize the connections list */
	if (!connset_init(&hs->connset)) {
		return (false);
	}

	/* Initialize the transaction & sessions list */
	list_init(&hs->sessions);

	/* User provided options and callbacks */
	hs->user		= user;

	hs->top			= f_top;
	hs->tail		= f_tail;
	hs->accept		= f_accept;
	hs->header		= f_header;
	hs->handle		= f_handle;
	hs->bodyfwd_done	= f_bodyfwd_done;
	hs->done		= f_done;
	hs->close		= f_close;

	return (true);
}

bool
httpsrv_start(httpsrv_t *hs, const char *hostname, unsigned int port, unsigned int numworkers) {
	unsigned int	i;

	/* Listen on the HTTP port (forwarded to from mod_hs) */
	if (!conn_create_listen(&hs->connset,
				hostname, IPPROTO_TCP, port)) {
		log_err( "conn_create_listen()");
		return (false);
	}

	/* Launch a few HTTP worker threads */
	for (i = 0; i < numworkers; i++) {
		if (!thread_add("HTTPWorker", &httpsrv_worker_thread, hs)) {
			log_err( "could not create thread");
			return (false);
		}
	}

	if (!thread_add("HTTPPoller", &httpsrv_poller_thread, hs)) {
		log_err( "could not create thread");
		return (false);
	}

	return (true);
}
