#ifndef DB_H
#define DB_H 1
#define IN_DB_H 1

/* Can only have one database layer */
#include "db_psql.h"

typedef enum {
	DB_T_NONE = 0,		/* None (also end marker for dbfield_t) */
	DB_T_STRING,		/* String */
	DB_T_ENUM,		/* Number */
	DB_T_UINT32,		/* 32bit Unsigned integer */
	DB_T_UINT64,		/* 64bit Unsigned integer */
	DB_T_BOOL		/* Boolean */
} dbtype_t;

typedef struct {
	const char	*name;	/* Name of the field */
	dbtype_t	type;	/* Type of the field */
} dbfield_t;

typedef enum {
	DB_R_OK,		/* Everything OK */
	DB_R_DUPLICATE_KEY,	/* The (INSERT) caused a duplicate key */
	DB_R_ERR		/* Other errors */
} dbreply_t;

/* Generic database schema loader */
bool db_setupschema(const char *dbname, const char *dbuser,
		    const char *schema);

/* For the implementation (db_psql etc) to implement */
bool db_init(dbconn_t *db, const char *dbname, const char *dbuser);
void db_cleanup(dbconn_t *db);

void db_initres(dbres_t *result);

dbreply_t db_query(dbconn_t *db, dbres_t *result, const char *caller,
		   const char *txt, ...);
void db_query_finish(dbconn_t *db, dbres_t *result);

int db_result_columnno(dbres_t *result, const char *field);
unsigned int db_result_getnumrows(dbres_t *result);

bool db_result_initcolcache(dbres_t *result, const dbfield_t *fields,
			    int *colcache);
bool db_result_get(dbres_t *result, unsigned int row, const dbfield_t *fields,
                   int *colcache, void **results);

bool db_result_get_string(dbres_t *result, unsigned int row,
                          unsigned int column, const char **str);
bool db_result_get_enum(dbres_t *result, unsigned int row,
                        unsigned int column, const char **str);
bool db_result_get_uint32(dbres_t *result, unsigned int row,
                          unsigned int column, uint32_t *t32);
bool db_result_get_uint64(dbres_t *result, unsigned int row,
                          unsigned int column, uint64_t *t64);
bool db_result_get_bool(dbres_t *result, unsigned int row,
                        unsigned int column, bool *b);

bool db_result_field_bool(dbres_t *result, const char *caller,
			  unsigned int row, const char *field,
			  bool *b);
bool db_result_field_string(dbres_t *result, const char *caller,
			    unsigned int row, const char *field,
			    const char **string);
bool db_result_field_uint32(dbres_t *result, const char *caller,
			    unsigned int row, const char *field,
			    uint32_t *t32);
bool db_result_field_uint64(dbres_t *result, const char *caller,
			    unsigned int row, const char *field,
			    uint64_t *t64);

bool db_setup(const char *dbname, const char *dbuser);
bool db_create(dbconn_t *db, unsigned int num_types, const char **types,
	       const char **typeQs, unsigned int num_tables,
	       const char **tables, const char **tableQs);

void db_set_notices(dbconn_t *db, bool notices);
bool db_set_keeptrying(dbconn_t *db, bool keeptrying);

#undef IN_DB_H
#endif /* DB_H */
