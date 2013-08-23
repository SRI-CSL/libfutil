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
	char		uri[1024];
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
typedef bool (*httpsrv_done_f)(httpsrv_client_t *cl, void *user);
typedef void (*httpsrv_line_f)(httpsrv_client_t *cl, void *user, char *line);

/* All private */
typedef struct {
	uint64_t		id;		/* Identifier for debugging */
	connset_t		connset;	/* Connections */
	hlist_t			sessions;	/* Sessions */

	/* Caller functions (callbacks) */
	/* User data */
	void			*user;

	/* HTML Top function - called to generate the top of a HTML page */
	httpsrv_f		top;

	/* HTML Top function - called to generate the tail of a HTML page */
	httpsrv_f		tail;

	/* Accept function - called when connection is accepted */
	httpsrv_f		accept;

	/* Header function - called for every header */
	httpsrv_line_f		header;

	/* Handle function - called when request is complete */
	httpsrv_done_f		handle;

	/* BodyFWDdone     - called when BodyFwd is complete */
	httpsrv_f		bodyfwd_done;

	/* Done function   - called when request is done */
	httpsrv_f		done;

	/* Close function  - called when closing connection */
	httpsrv_f		close;
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
	uint64_t		bodyfwd_len;	/* Length still to forward */

	char			*readbody;	/* POST body destination */
	uint64_t		readbody_len;	/* How much of the body to read */
	uint64_t		readbody_off;	/* How much already read */
	uint64_t		readbody_siz;	/* How large the buffer really is */

	uint64_t		skipbody_len;	/* Skip this many bytes */
};

#define HCL_IDn "%" PRIu64
#define HCL_ID "[hcl" HCL_IDn "]"

bool httpsrv_init(httpsrv_t *hs, void *user,
			httpsrv_f top,
			httpsrv_f tail,
			httpsrv_f accept,
			httpsrv_line_f header,
			httpsrv_done_f handle,
			httpsrv_f bodyfwd_done,
			httpsrv_f done,
			httpsrv_f close);
bool httpsrv_start(httpsrv_t *hs, const char *hostname, unsigned int port, unsigned int numworkers);
void httpsrv_exit(httpsrv_t *hs);

httpsrv_client_t *httpsrv_newcl(httpsrv_t *hs);

void httpsrv_done(httpsrv_client_t *hcl);
void httpsrv_args(httpsrv_client_t *hcl, httpsrv_argl_t *a);

const char *httpsrv_methodname(unsigned int method);
void httpsrv_close(httpsrv_client_t *hcl);
void httpsrv_set_userdata(httpsrv_client_t *hcl, void *user);
bool httpsrv_parse_request(httpsrv_client_t *hcl);
void httpsrv_silence(httpsrv_client_t *hcl);
void httpsrv_speak(httpsrv_client_t *hcl);
void httpsrv_forward(httpsrv_client_t *hin, httpsrv_client_t *hout);

int httpsrv_readbody_alloc(httpsrv_client_t *hcl, uint64_t min, uint64_t max);
void httpsrv_readbody_free(httpsrv_client_t *hcl);

void httpsrv_sessions(httpsrv_client_t *hcl);

#endif /* HTTPSRV_H */

