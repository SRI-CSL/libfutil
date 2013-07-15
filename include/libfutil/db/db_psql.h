#ifndef DB_PSQL_H
#define DB_PSQL_H 1

#ifndef IN_DB_H
#error "Can only be included from db.h" 
#endif

#include <libfutil/misc.h>
#include <libpq-fe.h>

/* Taken from <postgresql/catalog/pg_type.h> which is not for client apps apparently */
enum {
	BOOLOID		= 16,
	INT8OID		= 20,
	INT4OID		= 23,
	TEXTOID		= 25,
	CIDROID		= 650,
	INETOID		= 869,
	VARCHAROID	= 1043,
	INTERVALOID	= 1186
};

/* We need to cover up those opaque types*/
struct dbconn {
	char		*conninfo;
	const char	*dbname;
	const char	*dbuser;
	PGconn		*conn;
	mutex_t		mutex;
	bool		notices;
	bool		keeptrying;
	char		q[1024];
};

struct dbres {
	PGresult	*res;
};

typedef struct dbconn	dbconn_t;
typedef struct dbres	dbres_t;

#endif /* DB_PSQL_H */

