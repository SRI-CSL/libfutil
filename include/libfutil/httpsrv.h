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
	char		rawuri[8192];
	char		uri[8192];
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
typedef void (*httpsrv_sf)(httpsrv_client_t *hcl);
typedef void (*httpsrv_f)(httpsrv_client_t *hcl, void *user);
typedef bool (*httpsrv_done_f)(httpsrv_client_t *hcl, void *user);
typedef void (*httpsrv_line_f)(httpsrv_client_t *hcl, void *user, char *line);
typedef void (*httpsrv_bfwd_f)(httpsrv_client_t *hcl, httpsrv_client_t *fhcl, void *user);

/* All private */
typedef struct {
	uint64_t		id;		/* Identifier for debugging */
	mutex_t			mutex;		/* Lock */
	connset_t		connset;	/* Connections */
	hlist_t			sessions;	/* Sessions */

	/* Caller functions (callbacks) */
	/* User data */
	void			*user;

	/* HTML Top function	- called to generate the top of a HTML page */
	httpsrv_f		top;

	/* HTML Top function	- called to generate the tail of a HTML page */
	httpsrv_f		tail;

	/* Accept function	- called when connection is accepted */
	httpsrv_f		accept;

	/* Header function	- called for every header */
	httpsrv_line_f		header;

	/* Handle function	- called when request is complete */
	httpsrv_done_f		handle;

	/* BodyFWDdone		- called when BodyFwd is complete */
	httpsrv_bfwd_f		bodyfwd_done;

	/* Done function	- called when request is done */
	httpsrv_f		done;

	/* Close function	- called when closing connection */
	httpsrv_f		close;
} httpsrv_t;

/* Per-connection/session from mod_dgw or listeners */
struct httpsrv_client {
	hnode_t			node;		/* Session list node */
	uint64_t		id;		/* Unique ID */
	uint64_t		reqid;		/* Number of request handled */
	uint64_t		starttime;	/* Time started */
	uint64_t		lastact;	/* Time of last activity */
	httpsrv_t		*hs;		/* HTTP Server */
	conn_t			conn;		/* Connection */
	http_method_t		method;		/* HTTP Method */
	char			the_request[4096]; /* Full HTTP request */
	buf_t			the_headers;	/* All headers (raw) */
	httpsrv_headers_t	headers;	/* Inbound headers */
	bool			close;		/* Close it? */
	bool			keephandling;	/* Keep Handling it? */
	void			*user;		/* User data */

	httpsrv_client_t	*bodyfwd;	/* Forward the body? */
	uint64_t		bodyfwd_len;	/* Length still to forward */

	char			*readbody;	/* POST body destination */
	uint64_t		readbody_len;	/* How much of the body to read */
	uint64_t		readbody_off;	/* How much already read */
	uint64_t		readbody_siz;	/* How large the buffer really is */

	uint64_t		skipbody_len;	/* Skip this many bytes */

	/* Temp set by user for doing small things after conn_handled() */
	/* Typically used for changing processing lists to avoid races */
	httpsrv_sf		posthandle;
};

#define HCL_IDn "%" PRIu64
#define HCL_ID "[hcl" HCL_IDn "]"

bool httpsrv_init(httpsrv_t *hs, void *user,
			httpsrv_f top,
			httpsrv_f tail,
			httpsrv_f accept,
			httpsrv_line_f header,
			httpsrv_done_f handle,
			httpsrv_bfwd_f bodyfwd_done,
			httpsrv_f done,
			httpsrv_f close);
bool httpsrv_start(httpsrv_t *hs, const char *hostname, unsigned int port, unsigned int numworkers);
void httpsrv_exit(httpsrv_t *hs);

httpsrv_client_t *httpsrv_newcl(httpsrv_t *hs);
void httpsrv_client_destroy(httpsrv_client_t *hcl);

void httpsrv_done(httpsrv_client_t *hcl);
void httpsrv_args(httpsrv_client_t *hcl, httpsrv_argl_t *a);

const char *httpsrv_methodname(unsigned int method);
void httpsrv_close(httpsrv_client_t *hcl);

void httpsrv_set_userdata(httpsrv_client_t *hcl, void *user);
void *httpsrv_get_userdata(httpsrv_client_t *hcl);
void httpsrv_set_posthandle(httpsrv_client_t *hcl, httpsrv_sf f);

bool httpsrv_parse_request(httpsrv_client_t *hcl);

void httpsrv_forward(httpsrv_client_t *hin, httpsrv_client_t *hout);

void httpsrv_sendfile(httpsrv_client_t *hin, const char *file);

int httpsrv_readbody_alloc(httpsrv_client_t *hcl, uint64_t min, uint64_t max);
void httpsrv_readbody_free(httpsrv_client_t *hcl);

void httpsrv_sessions(httpsrv_client_t *hcl);

#define HTTPSRV_HTTP_OK		200, "OK"
#define HTTPSRV_HTTP_FORBIDDEN	403, "Forbidden"
#define HTTPSRV_HTTP_NOTFOUND	404, "Not Found"

#define HTTPSRV_CTYPE_HTML	"text/html;charset=UTF-8"
#define HTTPSRV_CTYPE_CSS	"text/css;charset=UTF-8"
#define HTTPSRV_CTYPE_JSON	"application/json"
#define HTTPSRV_CTYPE_JPEG	"image/jpeg"
#define HTTPSRV_CTYPE_PNG	"image/png"
#define HTTPSRV_CTYPE_BINARY	"application/binary"

void httpsrv_answer(httpsrv_client_t *hcl, unsigned int code, const char *msg, const char *ctype);
void httpsrv_error(httpsrv_client_t *hcl, unsigned int code, const char *msg);

/* Force, 10 minutes, 24 hours */
#define HTTPSRV_EXPIRE_FORCE	(0)
#define HTTPSRV_EXPIRE_SHORT	(60*10)
#define HTTPSRV_EXPIRE_LONG	(60*60*24)
void httpsrv_expire(httpsrv_client_t *hcl, unsigned int maxage);

#endif /* HTTPSRV_H */

