#include <libfutil/db/db.h>

/*
 * Note: This is actually PostgreSQL specific due to the datatypes
 * (INET is not standard SQL)
 */
bool
db_setupschema(const char *dbname, const char *dbuser, const char *schema)
{
	char		q[2048], line[128];
	dbconn_t	db;
	dbres_t		res;
	dbreply_t	drep = DB_R_OK;
	unsigned int	l, ql = 0, linenum = 0;
	FILE		*f;

	f = fopen(schema, "r");
	if (!f) {
		/* Try also in /usr/share/saferdefiance/ */
		snprintf(q, sizeof q, "/usr/share/saferdefiance/%s", schema);
		f = fopen(q, "r");
	}

	if (!f) {
		log_alt("Could not find schema %s, "
			"please change directory to location of the schema",
			schema);
			return (false);
	}

	/* Init */
	memzero(q, sizeof q);

	db_init(&db, dbname, dbuser);
	db_initres(&res);

	/* Notices are not very useful */
	db_set_notices(&db, false);

	while (fgets(line, sizeof line, f) != NULL) {
		l = strlen(line);
		linenum++;

		/* \n on a single line */
		if (l == 1)
			continue;

		/* One less */
		l--;

		/* Comment line? */
		if (line[0] == '#') {
			continue;
		}

		/* Trim \r + \n off the back */
		while (line[l] == '\r' || line[l] == '\n')
			line[l--] = '\0';

		/* Need to include the last char */
		l++;

		/* Append it to the query */
		if (sizeof q - ql <= l) {
			log_err( "Line %u too long", linenum);
			drep = DB_R_ERR;
			break;
		}

		/* Just add it */
		memcpy(&q[ql], line, l);
		ql += l;

		/* Semicolon at the end means end of query */
		/* No semi-column, then fetch next line */
		if (q[ql-1] != ';')
			continue;

		/* Full command, execute */
		drep = db_query(&db, &res, __func__, q);
		db_query_finish(&db, &res);
		if (drep != DB_R_OK) {
			log_err( "Query(%s) failed (line: %u)",
				q, linenum);
			break;
		}

		/* Next */
		memzero(q, sizeof q);
		ql = 0;
	}

	if (drep == DB_R_OK && strlen(q) > 0) {
		log_wrn(
			"Left over string in query buffer: %s",
			q);
		drep = DB_R_OK;
	}

	fclose(f);
	db_cleanup(&db);

	return (drep == DB_R_OK ? true : false);
}

bool
db_result_initcolcache(dbres_t *result, const dbfield_t *fields,
		       int *colcache)
{
	unsigned int	c;
	bool		ret = true;

	for (c = 0; fields[c].type != DB_T_NONE; c++) {
		colcache[c] = db_result_columnno(result, fields[c].name);
		if (colcache[c] == -1) {
			log_err( "Missing column %s, check the SQL",
				fields[c].name);

			/* We fail at the end thus showing all missing fields */
			ret = false;
		}
	}

	return (ret);
}

bool
db_result_get(dbres_t *result, unsigned int row, const dbfield_t *fields,
	      int *colcache, void **results)
{
	unsigned int c;

	for (c = 0; fields[c].type != DB_T_NONE; c++) {
		/* Skip fields that do not want a result */
		if (results[c] == NULL)
			continue;

		switch (fields[c].type)
		{
		case DB_T_STRING:
			if (!db_result_get_string(result, row,
						  colcache[c], results[c])) {
				log_err(
					"field '%s' is not a string",
					fields[c].name);
				return (false);
			}
			break;

		case DB_T_ENUM:
			if (!db_result_get_enum(result, row,
						  colcache[c], results[c])) {
				log_err(
					"field '%s' is not an enum",
					fields[c].name);
				return (false);
			}
			break;

		case DB_T_UINT32:
			if (!db_result_get_uint32(result, row,
						  colcache[c], results[c])) {
				log_err(
					"field '%s' is not a uint32",
					fields[c].name);
				return (false);
			}
			break;

		case DB_T_UINT64:
			if (!db_result_get_uint64(result, row,
						  colcache[c], results[c])) {
				log_err(
					"field '%s' is not a uint64",
					fields[c].name);
				return (false);
			}
			break;

		case DB_T_BOOL:
			if (!db_result_get_bool(result, row,
						  colcache[c], results[c])) {
				log_err(
					"field '%s' is not a boolean",
					fields[c].name);
				return (false);
			}
			break;

		default:
			return (false);
                }
	}

	return (true);
}

