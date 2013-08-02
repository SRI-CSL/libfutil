#ifndef HTTPSRV_H
#define HTTPSRV_H 1

#include "misc.h"
#include "conn.h"

typedef enum {
	HTTP_M_NONE = 0,
	HTTP_M_GET,
	HTTP_M_HEAD,
	HTTP_M_POST,
	HTTP_M_PUT,
	HTTP_M_DELETE,
	HTTP_M_TRACE,
	HTTP_M_OPTIONS,
	HTTP_M_CONNECT,
	HTTP_M_PATCH,
	HTTP_M_MAX
} http_method_t;

struct http_method {
	const char	name[12];
	unsigned int	len;
};

typedef struct {
	char		*var;
	char		*val;
} httpsrv_arg_t;

typedef struct {
	const char	*var;
	char		**val;
} httpsrv_argl_t;

typedef struct {
	char		remote_ip[128];
	char		remote_port_s[8];
	uint32_t	remote_port;
	char		local_ip[128];
	char		local_port_s[8];
	uint32_t	local_port;
	char		hostname[256];
	char		uri[512];
	char		args[4096];
	char		cookie[4096];
	char		content_type[256];
	char		content_length_s[32];
	uint64_t	content_length;

	/* Pre-split version of args */
	unsigned int	argc;
	char		argsplit[4096];
	httpsrv_arg_t	argi[128];
} httpsrv_headers_t;

typedef struct httpsrv_client httpsrv_client_t;
typedef void (*httpsrv_f)(httpsrv_client_t *cl, void *user);
typedef void (*httpsrv_line_f)(httpsrv_client_t *cl, void *user, char *line);

/* All private */
typedef struct {
	uint64_t		id;		/* Identifier for debugging */
	connset_t		connset;	/* Connections */
	hlist_t			sessions;	/* Sessions */

	/* Caller functions (callbacks) */
	void			*user;		/* User data */
	httpsrv_f		accept;		/* Accept function - called when connection is accepted */
	httpsrv_line_f		header;		/* Header function - called for every header */
	httpsrv_f		handle;		/* Handle function - called when request is complete */
	httpsrv_f		bodyfwddone;	/* BodyFWDdone     - called when BodyFwd is complete */
	httpsrv_f		done;		/* Done function   - called when request is done */
	httpsrv_f		close;		/* Close function  - called when closing connection */
} httpsrv_t;

/* Per-connection/session from mod_dgw or listeners */
struct httpsrv_client {
	hnode_t			node;		/* Session list node */
	uint64_t		id;		/* Unique ID */
	uint64_t		reqid;		/* Number of request handled */
	time_t			starttime;	/* Time started */
	time_t			lastact;	/* Time of last activity */
	httpsrv_t		*hs;		/* HTTP Server */
	conn_t			conn;		/* Connection */
	http_method_t		method;		/* HTTP Method */
	char			the_request[4096]; /* Full HTTP request */
	buf_t			the_headers;	/* All headers (raw) */
	httpsrv_headers_t	headers;	/* Inbound headers */
	bool			close;		/* Close it? */
	bool			busy;		/* Busy with a request? */
	void			*user;		/* User data */
	httpsrv_client_t	*bodyfwd;	/* Forward the body? */
	uint64_t		bodyfwdlen;	/* Length still to forward */

	char			*readbody;	/* POST body destination */
	uint64_t		readbodylen;	/* How much of the body to read */
	uint64_t		readbodyoff;	/* How much already read */
};

bool httpsrv_init(httpsrv_t *hs, void *user,
			httpsrv_f accept,
			httpsrv_line_f header,
			httpsrv_f handle,
			httpsrv_f bodyfwddone,
			httpsrv_f done,
			httpsrv_f close);
bool httpsrv_start(httpsrv_t *hs, const char *hostname, unsigned int port, unsigned int numworkers);
void httpsrv_exit(httpsrv_t *hs);

void httpsrv_done(httpsrv_client_t *hcl);
void httpsrv_args(httpsrv_client_t *hcl, httpsrv_argl_t *a);

const char *httpsrv_methodname(unsigned int method);
void httpsrv_close(httpsrv_client_t *hcl);
void httpsrv_set_userdata(httpsrv_client_t *hcl, void *user);
bool httpsrv_parse_request(httpsrv_client_t *hcl);
void httpsrv_silence(httpsrv_client_t *hcl);
void httpsrv_speak(httpsrv_client_t *hcl);

#endif /* HTTPSRV_H */

