#ifndef CONN_H
#define CONN_H 1

#include "misc.h"
#include "buf.h"
#include "list.h"

/* Optional OpenSSL support */
#ifdef CONN_SSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#endif

typedef struct {
	mutex_t		mutex;		/* Connset lock (for fd_*) */
	hlist_t		active;		/* Active connections in this set (polling) */
	hlist_t		ready;		/* Connections that are ready */
	hlist_t		inactive;	/* Inactive connections (no polling) */
	hlist_t		handling;	/* Connections being handled */

	fd_set		fd_read;	/* Read FDs */
	fd_set		fd_write;	/* Write FDs */

	uint64_t	id;		/* Set ID */
	int		hifd;		/* Highest FD */
} connset_t;

/* Apache also has a conn_state_t thus call ours connstate_t */

/* Please keep in sync with conn_set_stateA */
typedef enum {
	CONN_UNUSED = 0,
	CONN_LISTENING,
	CONN_ACCEPTING,
	CONN_CONNECTING,
	CONN_CONNECTED
} connstate_t;

typedef struct conn conn_t;

/* Hook called when flushing() which helps for debugging and testing */
typedef int (*conn_flush_hook)(void *data, unsigned int id, bool isheader,
				const char *buf, uint64_t length);

typedef void (*conn_posthandle_f)(conn_t *conn, void *user);

/* Per-connection context */
struct conn {
	hnode_t			node;		/* List node */
	mutex_t			mutex;		/* Mutex */
	socket_t		sock;		/* Socket */
	uint16_t		wntevents;	/* Wanted Socket events */
	uint16_t		hasevents;	/* Have   Socket events */
	hlist_t			*connset_l;	/* Which list it is on */
	connset_t		*connset;	/* Set this conn belongs to */
	void			*clientdata;	/* Client data */
	connstate_t		state;		/* Connection state */
	uint64_t		id;		/* Unique ID */
	uint32_t		protocol;	/* Protocol */
	uint32_t		port;		/* Port Number */

	time_t			last_connect;	/* Last connect time */
	time_t			last_sent;	/* Last sent time */
	time_t			last_recv;	/* Last receive time */

	conn_flush_hook		flush_hook;	/* Hook for conn_flush() */
	void			*flush_data;	/* Flush data */

	buf_t			recv;		/* Receive side */
	buf_t			send;		/* Sending side */
	buf_t			send_headers;	/* Headers to send */
	uint64_t		real_contentlen;/* Real content length */
	bool			add_contentlen;	/* Add Content-Length header? */

	conn_posthandle_f	posthandle_f;	/* Post Handling function */
	void			*posthandle_u;	/* User data */

	/* OpenSSL */
#ifdef CONN_SSL
	BIO			*ssl_bio_in;	/* Binary In */
	BIO			*ssl_bio_out;	/* Binary out */
	SSL			*ssl;		/* SSL Session */
	const char		*ssl_psk_key;	/* SSL PSK Key */
	const char		*ssl_psk_id;	/* SSL PSK Id */
	char			ssl_in[16*1024]; /* SSL Input */
	uint64_t		ssl_in_len;
	char			ssl_out[16*1024]; /* SSL Output */
	uint64_t		ssl_out_len;
#endif
};

/* Always defined (CONN_SSL) */
#ifdef CONN_SSL
SSL_CTX *conn_ssl_init(bool serverside);
void conn_ssl_cleanup(SSL_CTX *ssl_ctx);
bool conn_ssl_start(conn_t *conn, SSL_CTX *ssl_ctx, const char *ssl_psk_key,
		    const char *ssl_psk_id, bool serverside);
#endif

bool conn_init(conn_t *conn, void *clientdata);

void conn_destroy(conn_t *conn);
void conn_close(conn_t *conn);

bool conn_create_listen(connset_t *connset, const char *hostname,
			uint32_t protocol, uint32_t port);

bool conn_accept(conn_t *conn, conn_t *lconn, void *clientdata);

bool conn_getinfo(conn_t *conn, bool local, char *hostname, unsigned int hlen,
		  uint32_t *protocol, uint32_t *port);

bool conn_create_connection(conn_t *conn, const char *host, uint32_t protocol,
			    uint32_t port, connset_t *connset);

bool conn_connect(conn_t *conn, const char *host, uint32_t protocol,
		  uint32_t port);

void conn_events(conn_t *conn, uint16_t events);

bool conn_is_eof(conn_t *conn);

int conn_recv(conn_t *conn);
int conn_recvline(conn_t *conn, char *buf, unsigned int buflen);
void conn_recv_empty(conn_t *conn, uint64_t len);

uint64_t conn_flushleft(conn_t *conn);
bool conn_flush(conn_t *conn);

void conn_set_flush_hook(conn_t *conn, conn_flush_hook hook, void *data);
void conn_unset_flush_hook(conn_t *conn);

bool conn_addheaders(conn_t *conn, const char *txt);
bool conn_addheader(conn_t *conn, const char *txt);
bool conn_addheadervf(conn_t *conn, const char *fmt, va_list ap)
	ATTR_FORMAT(printf, 2, 0);
bool conn_addheaderf(conn_t *conn, const char *fmt, ...)
	ATTR_FORMAT(printf, 2, 3);
bool conn_putl(conn_t *conn, const char *txt, unsigned int len);
bool conn_put(conn_t *conn, const char *txt);
bool conn_copy(conn_t *in, conn_t *out);
uint64_t conn_copym(conn_t *in, conn_t *out, uint64_t max);
bool conn_vprintf(conn_t *conn, const char *fmt, va_list ap)
	ATTR_FORMAT(printf, 2, 0);
bool conn_printf(conn_t *conn, const char *fmt, ...)
	ATTR_FORMAT(printf, 2, 3);

#define CONN_IDn "c%" PRIu64 ""
#define CONN_ID "[" CONN_IDn "]"
#define CONNS_ID "[s%" PRIu64 "]"

#define SOCK_ID "[fd%d]"

#define conn_id(conn) ((conn) ? (conn)->id : 0)
#define conn_sock(conn) ((int)((conn) ? (conn)->sock : 0))
#define conn_protocol(conn) ((conn)->protocol)
#define conn_port(conn) ((conn)->port)
#define conn_type(conn) ((conn)->type)
#define conn_clientdata(conn) ((conn)->clientdata)

#define conn_buffer(conn) (buf_buffer(&(conn)->recv))
#define conn_buffer_max(conn) (buf_max(&(conn)->recv))
#define conn_buffer_cur(conn) (buf_cur(&(conn)->recv))
#define conn_buffer_left(conn) (buf_left(&(conn)->recv))
#define conn_buffer_empty(conn) (buf_empty(&(conn)->recv))
#define conn_buffer_shift(conn, len) (buf_shift(&(conn)->recv, len))
#define conn_buffer_isempty(conn) (buf_cur(&(conn)->recv) == 0)

#define conn_send_cur(conn) buf_cur(&(conn)->send)
#define conn_send_empty(conn) (buf_empty(&(conn)->send))
#define conn_send_isempty(conn) (buf_cur(&(conn)->send) == 0)

#define conn_set_real_contentlen(conn, len) (conn)->real_contentlen = (len)
#define conn_add_contentlen(conn, yesno) (conn)->add_contentlen = (yesno)

#define conn_header_empty(conn) (buf_empty(&(conn)->send_headers))

#define conn_state(conn) ((conn)->state)
void conn_set_state(conn_t *conn, connstate_t state);
#define conn_set_connected(conn) conn_set_state(conn, CONN_CONNECTED)

bool conn_is_state(conn_t *conn, connstate_t st);
#define conn_is_connected(conn) conn_is_state(conn, CONN_CONNECTED)
#define conn_is_connecting(conn) conn_is_state(conn, CONN_CONNECTING)
#define conn_is_there(conn) (((conn) != NULL) && ((conn)->id != 0))
#define conn_is_valid(conn) (conn_is_there(conn) && ((conn)->sock != INVALID_SOCKET))

#define conn_last_sent(conn) ((conn)->last_sent)
#define conn_last_recv(conn) ((conn)->last_recv)
#define conn_last_connect(conn) ((conn)->last_connect)

typedef enum {
	CONN_POLLNONE	= 0,
	CONN_POLLIN	= 1,
	CONN_POLLOUT	= 2
} connpoll_t;

bool conn_wnt_in(conn_t *conn);
bool conn_wnt_out(conn_t *conn);
bool conn_poll_in(conn_t *conn);
bool conn_poll_out(conn_t *conn);

void connset_init(connset_t *cs);
void connset_destroy(connset_t *cs);
int connset_poll(connset_t *cs);

conn_t *connset_get_one_ready(connset_t *cs);
conn_t *connset_get_ready(connset_t *cs);
void connset_handling_setup(conn_t *conn);
void connset_handling_done(conn_t *conn, bool keephandling);
void conn_set_posthandle(conn_t *conn, conn_posthandle_f f, void *user);

/* connset_poll() returns: < 0: error, 0: timeout, >0: ready sockets */

#define connset_is_empty(cs) (list_isempty(&(cs)->active) && \
			      list_isempty(&(cs)->ready) && \
			      list_isempty(&(cs)->inactive))

#endif /* CONN_H */
