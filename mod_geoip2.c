/*
 * ProFTPD: mod_geoip2 -- a module for looking up country/city/etc for clients
 * Copyright (c) 2019-2023 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Suite 500, Boston, MA 02110-1335, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_geoip2, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 *
 * --- DO NOT DELETE BELOW THIS LINE ----
 * $Libraries: -lmaxminddb$
 */

#include "conf.h"
#include "privs.h"

/* A lot of ideas for this module were liberally borrowed from the mod_geoip
 * module for Apache.
 */

#define MOD_GEOIP2_VERSION		"mod_geoip2/0.1.1"

/* Make sure the version of proftpd is as necessary. */
#if PROFTPD_VERSION_NUMBER < 0x0001030402
# error "ProFTPD 1.3.4rc2 or later required"
#endif

#include <maxminddb.h>

module geoip2_module;

static int geoip2_engine = FALSE;
static int geoip2_logfd = -1;

static pool *geoip2_pool = NULL;
static array_header *geoip2_mmdbs = NULL;

/* The types of data that GeoIP can provide, and that we care about. */
static const char *geoip_city = NULL;
static const char *geoip_postal_code = NULL;
static const char *geoip_latitude = NULL;
static const char *geoip_longitude = NULL;
static const char *geoip_org = NULL;
static const char *geoip_country_code2 = NULL;
static const char *geoip_country_name = NULL;
static const char *geoip_region_code = NULL;
static const char *geoip_region_name = NULL;
static const char *geoip_continent_code = NULL;
static const char *geoip_asn = NULL;
static const char *geoip_timezone = NULL;

/* Names of supported GeoIP values */
#define GEOIP_FILTER_KEY_COUNTRY_CODE		100
#define GEOIP_FILTER_KEY_COUNTRY_NAME		101
#define GEOIP_FILTER_KEY_REGION_CODE		102
#define GEOIP_FILTER_KEY_REGION_NAME		103
#define GEOIP_FILTER_KEY_CONTINENT		104
#define GEOIP_FILTER_KEY_ORGANIZATION		105
#define GEOIP_FILTER_KEY_CITY			106
#define GEOIP_FILTER_KEY_POSTAL_CODE		107
#define GEOIP_FILTER_KEY_LATITUDE		108
#define GEOIP_FILTER_KEY_LONGITUDE		109
#define GEOIP_FILTER_KEY_ASN			110
#define GEOIP_FILTER_KEY_TIMEZONE		111

struct geoip_filter_key {
  const char *filter_name;
  int filter_id;
};

static struct geoip_filter_key geoip_filter_keys[] = {
  { "CountryCode",	GEOIP_FILTER_KEY_COUNTRY_CODE },
  { "CountryName",	GEOIP_FILTER_KEY_COUNTRY_NAME },
  { "RegionCode",	GEOIP_FILTER_KEY_REGION_CODE },
  { "RegionName",	GEOIP_FILTER_KEY_REGION_NAME },
  { "Continent",	GEOIP_FILTER_KEY_CONTINENT },
  { "Organization",	GEOIP_FILTER_KEY_ORGANIZATION },
  { "City",		GEOIP_FILTER_KEY_CITY },
  { "PostalCode",	GEOIP_FILTER_KEY_POSTAL_CODE },
  { "Latitude",		GEOIP_FILTER_KEY_LATITUDE },
  { "Longitude",	GEOIP_FILTER_KEY_LONGITUDE },
  { "ASN",		GEOIP_FILTER_KEY_ASN },
  { "Timezone",		GEOIP_FILTER_KEY_TIMEZONE },

  { NULL, -1 }
};

#if PR_USE_REGEX
/* GeoIP filter */
struct geoip_filter {
  int filter_id;
  const char *filter_pattern;
  pr_regex_t *filter_re;
};
#endif /* PR_USE_REGEX */

/* GeoIP policies */
typedef enum {
  GEOIP_POLICY_ALLOW_DENY,
  GEOIP_POLICY_DENY_ALLOW

} geoip_policy_e;

static geoip_policy_e geoip_policy = GEOIP_POLICY_ALLOW_DENY;

static const char *trace_channel = "geoip2";

static const char *get_geoip_filter_name(int);
static const char *get_geoip_filter_value(int);

static int get_filter_id(const char *filter_name) {
  register unsigned int i;
  int filter_id = -1;

  for (i = 0; geoip_filter_keys[i].filter_name != NULL; i++) {
    if (strcasecmp(filter_name, geoip_filter_keys[i].filter_name) == 0) {
      filter_id = geoip_filter_keys[i].filter_id;
      break;
    }
  }

  return filter_id;
}

#if PR_USE_REGEX
static int get_filter(pool *p, const char *pattern, pr_regex_t **pre) {
  int res;

  *pre = pr_regexp_alloc(&geoip2_module);

  res = pr_regexp_compile(*pre, pattern, REG_EXTENDED|REG_NOSUB|REG_ICASE);
  if (res != 0) {
    char errstr[256];

    memset(errstr, '\0', sizeof(errstr));
    pr_regexp_error(res, *pre, errstr, sizeof(errstr)-1);
    pr_regexp_free(&geoip2_module, *pre);
    *pre = NULL;

    pr_log_pri(PR_LOG_DEBUG, MOD_GEOIP2_VERSION
      ": pattern '%s' failed regex compilation: %s", pattern, errstr);
    errno = EINVAL;
    return -1;
  }

  return res;
}

static struct geoip_filter *make_filter(pool *p, const char *filter_name,
    const char *pattern) {
  struct geoip_filter *filter;
  int filter_id;
  pr_regex_t *pre = NULL;

  filter_id = get_filter_id(filter_name);
  if (filter_id < 0) {
    pr_log_debug(DEBUG0, MOD_GEOIP2_VERSION ": unknown GeoIP filter name '%s'",
      filter_name);
    return NULL;
  }

  if (get_filter(p, pattern, &pre) < 0) {
    return NULL;
  }

  filter = pcalloc(p, sizeof(struct geoip_filter));
  filter->filter_id = filter_id;
  filter->filter_pattern = pstrdup(p, pattern);
  filter->filter_re = pre;

  return filter;
}

static array_header *get_sql_filters(pool *p, const char *query_name) {
  register unsigned int i;
  cmdtable *sql_cmdtab = NULL;
  cmd_rec *sql_cmd = NULL;
  modret_t *sql_res = NULL;
  array_header *sql_data = NULL;
  const char **values = NULL;
  array_header *sql_filters = NULL;

  sql_cmdtab = pr_stash_get_symbol2(PR_SYM_HOOK, "sql_lookup", NULL, NULL,
    NULL);
  if (sql_cmdtab == NULL) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "unable to execute SQLNamedQuery '%s': mod_sql not loaded", query_name);
    errno = EPERM;
    return NULL;
  }

  sql_cmd = pr_cmd_alloc(p, 2, "sql_lookup", query_name);

  sql_res = pr_module_call(sql_cmdtab->m, sql_cmdtab->handler, sql_cmd);
  if (sql_res == NULL ||
      MODRET_ISERROR(sql_res)) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "error processing SQLNamedQuery '%s'; check mod_sql logs for details",
      query_name);
    errno = EPERM;
    return NULL;
  }

  sql_data = sql_res->data;
  pr_trace_msg(trace_channel, 9, "SQLNamedQuery '%s' returned item count %d",
    query_name, sql_data->nelts);

  if (sql_data->nelts == 0) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "SQLNamedQuery '%s' returned no values", query_name);
    errno = ENOENT;
    return NULL;
  }

  if (sql_data->nelts % 2 == 1) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "SQLNamedQuery '%s' returned odd number of values (%d), "
      "expected even number", query_name, sql_data->nelts);
    errno = EINVAL;
    return NULL;
  }

  values = sql_data->elts;
  sql_filters = make_array(p, 0, sizeof(struct geoip_filter));

  for (i = 0; i < sql_data->nelts; i += 2) {
    const char *filter_name, *pattern = NULL;
    struct geoip_filter *filter;

    filter_name = values[i];
    pattern = values[i+1];

    filter = make_filter(p, filter_name, pattern);
    if (filter == NULL) {
      pr_trace_msg(trace_channel, 3, "unable to use '%s %s' as filter: %s",
        filter_name, pattern, strerror(errno));
      continue;
    }

    *((struct geoip_filter **) push_array(sql_filters)) = filter;
  }

  return sql_filters;
}
#endif /* PR_USE_REGEX */

static void resolve_deferred_patterns(pool *p, const char *directive) {
#if PR_USE_REGEX
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, directive, FALSE);
  while (c != NULL) {
    register unsigned int i;
    array_header *deferred_filters, *filters;

    pr_signals_handle();

    filters = c->argv[0];
    deferred_filters = c->argv[1];

    for (i = 0; i < deferred_filters->nelts; i++) {
      const char *query_name;
      array_header *sql_filters;

      query_name = ((const char **) deferred_filters->elts)[i];

      sql_filters = get_sql_filters(p, query_name);
      if (sql_filters == NULL) {
        continue;
      }

      array_cat(filters, sql_filters);
    }

    c = find_config_next(c, c->next, CONF_PARAM, directive, FALSE);
  }
#endif /* PR_USE_REGEX */
}

static void resolve_deferred_filters(pool *p) {
  resolve_deferred_patterns(p, "GeoIPAllowFilter");
  resolve_deferred_patterns(p, "GeoIPDenyFilter");
}

static int check_geoip_filters(geoip_policy_e policy) {
  int allow_conn = 0, matched_allow_filter = -1, matched_deny_filter = -1;
#if PR_USE_REGEX
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPAllowFilter", FALSE);
  while (c != NULL) {
    register unsigned int i;
    int matched = TRUE;
    array_header *filters;

    pr_signals_handle();

    if (matched_allow_filter == -1) {
      matched_allow_filter = FALSE;
    }

    filters = c->argv[0];

    for (i = 0; i < filters->nelts; i++) {
      int filter_id, res;
      struct geoip_filter *filter;
      pr_regex_t *filter_re;
      const char *filter_name, *filter_pattern, *filter_value;

      filter = ((struct geoip_filter **) filters->elts)[i];
      filter_id = filter->filter_id;
      filter_pattern = filter->filter_pattern;
      filter_re = filter->filter_re;

      filter_value = get_geoip_filter_value(filter_id);
      if (filter_value == NULL) {
        matched = FALSE;
        break;
      }

      filter_name = get_geoip_filter_name(filter_id);

      res = pr_regexp_exec(filter_re, filter_value, 0, NULL, 0, 0, 0);
      pr_trace_msg(trace_channel, 12,
        "%s filter value %s %s GeoIPAllowFilter pattern '%s'",
        filter_name, filter_value, res == 0 ? "matched" : "did not match",
        filter_pattern);
      if (res == 0) {
        (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
          "%s filter value '%s' matched GeoIPAllowFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);

      } else {
        (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
          "%s filter value '%s' did not match GeoIPAllowFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);
          matched = FALSE;
          break;
      }
    }

    if (matched == TRUE) {
      matched_allow_filter = TRUE;
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "GeoIPAllowFilter", FALSE);
  }

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPDenyFilter", FALSE);
  while (c != NULL) {
    register unsigned int i;
    int matched = TRUE;
    array_header *filters;

    pr_signals_handle();

    if (matched_deny_filter == -1) {
      matched_deny_filter = FALSE;
    }

    filters = c->argv[0];

    for (i = 0; i < filters->nelts; i++) {
      int filter_id, res;
      struct geoip_filter *filter;
      pr_regex_t *filter_re;
      const char *filter_name, *filter_pattern, *filter_value;

      filter = ((struct geoip_filter **) filters->elts)[i];
      filter_id = filter->filter_id;
      filter_pattern = filter->filter_pattern;
      filter_re = filter->filter_re;

      filter_value = get_geoip_filter_value(filter_id);
      if (filter_value == NULL) {
        matched = FALSE;
        break;
      }

      filter_name = get_geoip_filter_name(filter_id);

      res = pr_regexp_exec(filter_re, filter_value, 0, NULL, 0, 0, 0);
      pr_trace_msg(trace_channel, 12,
        "%s filter value %s %s GeoIPDenyFilter pattern '%s'",
        filter_name, filter_value, res == 0 ? "matched" : "did not match",
        filter_pattern);
      if (res == 0) {
        (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
          "%s filter value '%s' matched GeoIPDenyFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);
      } else {
        (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
          "%s filter value '%s' did not match GeoIPDenyFilter pattern '%s'",
          filter_name, filter_value, filter_pattern);
        matched = FALSE;
        break;
      }
    }

    if (matched == TRUE) {
      matched_deny_filter = TRUE;
      break;
    }

    c = find_config_next(c, c->next, CONF_PARAM, "GeoIPDenyFilter", FALSE);
  }
#endif /* !HAVE_REGEX_H or !HAVE_REGCOMP */

  switch (policy) {
    case GEOIP_POLICY_ALLOW_DENY:
      if (matched_deny_filter == TRUE &&
          matched_allow_filter != TRUE) {
        /* If we explicitly matched any deny filters AND have NOT explicitly
         * matched any allow filters, the connection is rejected, otherwise,
         * it is allowed.
         */
        (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
          "client matched GeoIPDenyFilter, rejecting connection");
        allow_conn = -1;

      } else {
        pr_trace_msg(trace_channel, 9,
          "allowing client connection (policy 'allow,deny')");
      }
      break;

    case GEOIP_POLICY_DENY_ALLOW:
      if (matched_allow_filter == FALSE) {
        /* If we have not explicitly matched any allow filters, then
         * reject the connection.
         */
        (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
          "client did not match any GeoIPAllowFilters, rejecting connection");
        allow_conn = -1;

      } else {
        pr_trace_msg(trace_channel, 9,
          "allowing client connection (policy 'deny,allow')");
      }
      break;
  }

  return allow_conn;
}

static const char *get_geoip_filter_name(int filter_id) {
  register unsigned int i;

  for (i = 0; geoip_filter_keys[i].filter_name != NULL; i++) {
    if (geoip_filter_keys[i].filter_id == filter_id) {
      return geoip_filter_keys[i].filter_name;
    }
  }

  errno = ENOENT;
  return NULL;
}

static const char *get_geoip_filter_value(int filter_id) {
  switch (filter_id) {
    case GEOIP_FILTER_KEY_COUNTRY_CODE:
      if (geoip_country_code2 != NULL) {
        return geoip_country_code2;
      }
      break;

    case GEOIP_FILTER_KEY_COUNTRY_NAME:
      if (geoip_country_name != NULL) {
        return geoip_country_name;
      }
      break;

    case GEOIP_FILTER_KEY_REGION_CODE:
      if (geoip_region_code != NULL) {
        return geoip_region_code;
      }
      break;

    case GEOIP_FILTER_KEY_REGION_NAME:
      if (geoip_region_name != NULL) {
        return geoip_region_name;
      }
      break;

    case GEOIP_FILTER_KEY_CONTINENT:
      if (geoip_continent_code != NULL) {
        return geoip_continent_code;
      }
      break;

    case GEOIP_FILTER_KEY_ORGANIZATION:
      if (geoip_org != NULL) {
        return geoip_org;
      }
      break;

    case GEOIP_FILTER_KEY_CITY:
      if (geoip_city != NULL) {
        return geoip_city;
      }
      break;

    case GEOIP_FILTER_KEY_POSTAL_CODE:
      if (geoip_postal_code != NULL) {
        return geoip_postal_code;
      }
      break;

    case GEOIP_FILTER_KEY_LATITUDE:
      if (geoip_latitude != NULL) {
        return geoip_latitude;
      }
      break;

    case GEOIP_FILTER_KEY_LONGITUDE:
      if (geoip_longitude != NULL) {
        return geoip_longitude;
      }
      break;

    case GEOIP_FILTER_KEY_ASN:
      if (geoip_asn != NULL) {
        return geoip_asn;
      }
      break;

    case GEOIP_FILTER_KEY_TIMEZONE:
      if (geoip_timezone != NULL) {
        return geoip_timezone;
      }
      break;
  }

  errno = ENOENT;
  return NULL;
}

static void get_geoip_tables(void) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPTable", FALSE);
  while (c != NULL) {
    MMDB_s *mmdb = NULL;
    const char *path;
    uint32_t flags;
    int res, xerrno = 0;

    pr_signals_handle();

    path = c->argv[0];
    flags = *((uint32_t *) c->argv[1]);
    mmdb = pcalloc(geoip2_pool, sizeof(MMDB_s));

    PRIVS_ROOT
    res = MMDB_open(path, flags, mmdb);
    xerrno = errno;
    PRIVS_RELINQUISH

    if (res == MMDB_SUCCESS) {
      char build_date[64];
      time_t build_epoch;

      *((MMDB_s **) push_array(geoip2_mmdbs)) = mmdb;

      build_epoch = mmdb->metadata.build_epoch;
      strftime(build_date, sizeof(build_date), "%F %T UTC",
        gmtime(&build_epoch));

      pr_trace_msg(trace_channel, 15,
        "loaded GeoIP table '%s': %s (IP version = IPv%d, format version = "
        "%d.%d, built = %s)", path, mmdb->metadata.database_type,
        mmdb->metadata.ip_version, mmdb->metadata.binary_format_major_version,
        mmdb->metadata.binary_format_minor_version, build_date);

    } else {
      if (res != MMDB_IO_ERROR) {
        pr_log_pri(PR_LOG_WARNING, MOD_GEOIP2_VERSION
          ": warning: unable to open/use GeoIPTable '%s': %s", path,
          MMDB_strerror(res));

      } else {
        pr_log_pri(PR_LOG_WARNING, MOD_GEOIP2_VERSION
          ": warning: unable to open/use GeoIPTable '%s': %s (%s)", path,
          MMDB_strerror(res), strerror(xerrno));
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "GeoIPTable", FALSE);
  }
}

static void remove_geoip_tables(void) {
  register unsigned int i;
  MMDB_s **mmdbs;

  if (geoip2_mmdbs == NULL ||
      geoip2_mmdbs->nelts == 0) {
    return;
  }

  mmdbs = geoip2_mmdbs->elts;
  for (i = 0; i < geoip2_mmdbs->nelts; i++) {
    if (mmdbs[i] != NULL) {
      MMDB_close(mmdbs[i]);
      mmdbs[i] = NULL;
    }
  }
}

static const char *get_geoip_data_text(pool *p, MMDB_lookup_result_s *lookup,
    const char **lookup_path, int filter_id) {
  int res, xerrno = 0;
  const char *text = NULL;
  MMDB_entry_data_s entry_data;

  res = MMDB_aget_value(&(lookup->entry), &entry_data, lookup_path);
  xerrno = errno;

  if (res != MMDB_SUCCESS) {
    const char *lookup_name;

    lookup_name = get_geoip_filter_name(filter_id);

    switch (res) {
      case MMDB_LOOKUP_PATH_DOES_NOT_MATCH_DATA_ERROR:
        /* Ignored. */
        errno = ENOENT;
        break;

      case MMDB_IO_ERROR:
        pr_trace_msg(trace_channel, 3, "error getting data for %s: %s (%s)",
          lookup_name, MMDB_strerror(res), strerror(xerrno));
        errno = xerrno;
        break;

      default:
        pr_trace_msg(trace_channel, 3, "error getting data for %s: %s",
          lookup_name, MMDB_strerror(res));
        errno = EPERM;
        break;
    }

    return NULL;
  }

  if (!entry_data.has_data) {
    errno = ENOENT;
    return NULL;
  }

  switch (entry_data.type) {
    case MMDB_DATA_TYPE_UTF8_STRING:
      text = pstrndup(p, entry_data.utf8_string, entry_data.data_size);
      break;

    case MMDB_DATA_TYPE_UINT32: {
      char buf[64];

      memset(buf, '\0', sizeof(buf));
#if PROFTPD_VERSION_NUMBER >= 0x0001030705
      pr_snprintf(buf, sizeof(buf)-1, "%lu", (unsigned long) entry_data.uint32);
#else
      snprintf(buf, sizeof(buf)-1, "%lu", (unsigned long) entry_data.uint32);
#endif /* ProFTPD 1.3.7 */
      text = pstrdup(p, buf);
      break;
    }

    case MMDB_DATA_TYPE_DOUBLE: {
      char buf[64];

      memset(buf, '\0', sizeof(buf));
#if PROFTPD_VERSION_NUMBER >= 0x0001030705
      pr_snprintf(buf, sizeof(buf)-1, "%f", entry_data.double_value);
#else
      snprintf(buf, sizeof(buf)-1, "%f", entry_data.double_value);
#endif /* ProFTPD 1.3.7 */
      text = pstrdup(p, buf);
      break;
    }

    default:
      pr_trace_msg(trace_channel, 3,
        "unknown/unsupported entry data type (%lu), ignoring",
        (unsigned long) entry_data.type);
      errno = EINVAL;
      return NULL;
  }

  return text;
}

static void get_geoip_data(void) {
  register unsigned int i;
  const char *ip_addr, *text;
  const char *lookup_path[5] = { NULL, NULL, NULL, NULL, NULL };
  MMDB_s **mmdbs;

  ip_addr = pr_netaddr_get_ipstr(session.c->remote_addr);

  mmdbs = geoip2_mmdbs->elts;
  for (i = 0; i < geoip2_mmdbs->nelts; i++) {
    MMDB_s *mmdb;
    MMDB_lookup_result_s lookup;
    int gai_error = 0, mmdb_error = 0;

    pr_signals_handle();

    if (mmdbs[i] == NULL) {
      continue;
    }

    mmdb = mmdbs[i];
    lookup = MMDB_lookup_string(mmdb, ip_addr, &gai_error, &mmdb_error);
    if (mmdb_error != MMDB_SUCCESS) {
      pr_trace_msg(trace_channel, 2,
        "error looking up '%s' in GeoIPTable '%s': %s", ip_addr,
        mmdb->filename, MMDB_strerror(mmdb_error));
      continue;
    }

    if (!lookup.found_entry) {
      pr_trace_msg(trace_channel, 2,
        "no entry found for '%s' in GeoIPTable '%s'", ip_addr, mmdb->filename);
      continue;
    }

    /* XXX This cries out to be done in a table-driven fashion. */

    lookup_path[0] = "country";
    lookup_path[1] = "iso_code";
    lookup_path[2] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_COUNTRY_CODE);
    if (text != NULL) {
      geoip_country_code2 = text;
    }

    /* "country" already set as first element above; no need to duplicate
     * it again.
     */
    lookup_path[1] = "names";
    lookup_path[2] = "en";
    lookup_path[3] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_COUNTRY_NAME);
    if (text != NULL) {
      geoip_country_name = text;
    }

    lookup_path[0] = "continent";
    lookup_path[1] = "code";
    lookup_path[2] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_CONTINENT);
    if (text != NULL) {
      geoip_continent_code = text;
    }

    lookup_path[0] = "subdivisions";
    lookup_path[1] = "0";
    lookup_path[2] = "iso_code";
    lookup_path[3] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_REGION_CODE);
    if (text != NULL) {
      geoip_region_code = text;
    }

    /* "subdivisions" already set as first element above; no need to duplicate
     * it again.
     */
    lookup_path[1] = "0";
    lookup_path[2] = "names";
    lookup_path[3] = "en";
    lookup_path[4] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_REGION_NAME);
    if (text != NULL) {
      geoip_region_name = text;
    }

    lookup_path[0] = "city";
    lookup_path[1] = "names";
    lookup_path[2] = "en";
    lookup_path[3] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_CITY);
    if (text != NULL) {
      geoip_city = text;
    }

    lookup_path[0] = "postal";
    lookup_path[1] = "code";
    lookup_path[2] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_POSTAL_CODE);
    if (text != NULL) {
      geoip_postal_code = text;
    }

    lookup_path[0] = "locations";
    lookup_path[1] = "latitude";
    lookup_path[2] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_LATITUDE);
    if (text != NULL) {
      geoip_latitude = text;
    }

    /* "locations" already set as first element above; no need to duplicate
     * it again.
     */
    lookup_path[1] = "longitude";
    lookup_path[2] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_LONGITUDE);
    if (text != NULL) {
      geoip_longitude = text;
    }

    /* "locations" already set as first element above; no need to duplicate
     * it again.
     */
    lookup_path[1] = "time_zone";
    lookup_path[2] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_TIMEZONE);
    if (text != NULL) {
      geoip_longitude = text;
    }

    lookup_path[0] = "autonomous_system_number";
    lookup_path[1] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_ASN);
    if (text != NULL) {
      geoip_asn = text;
    }

    lookup_path[0] = "autonomous_system_organization";
    lookup_path[1] = NULL;
    text = get_geoip_data_text(geoip2_pool, &lookup, lookup_path,
      GEOIP_FILTER_KEY_ORGANIZATION);
    if (text != NULL) {
      geoip_org = text;
    }
  }
}

static void get_geoip_info(void) {
  const char *ip_addr;

  get_geoip_data();

  ip_addr = pr_netaddr_get_ipstr(session.c->remote_addr);

  if (geoip_country_code2 != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: 2-Letter country code: %s", ip_addr,
      geoip_country_code2);
  }

  if (geoip_country_name != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Country name: %s", ip_addr,
      geoip_country_name);
  }

  if (geoip_region_code != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Region code: %s", ip_addr,
      geoip_region_code);
  }

  if (geoip_region_name != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Region name: %s", ip_addr,
      geoip_region_name);
  }

  if (geoip_timezone != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Timezone: %s", ip_addr, geoip_timezone);
  }

  if (geoip_continent_code != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Continent code: %s", ip_addr,
      geoip_continent_code);
  }

  if (geoip_org != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Organization: %s", ip_addr, geoip_org);
  }

  if (geoip_city != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: City: %s", ip_addr, geoip_city);
  }

  if (geoip_postal_code != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Postal code: %s", ip_addr,
      geoip_postal_code);
  }

  if (geoip_latitude != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Latitude: %s", ip_addr,
      geoip_latitude);
  }

  if (geoip_longitude != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: Longitude: %s", ip_addr,
      geoip_longitude);
  }

  if (geoip_asn != NULL) {
    pr_trace_msg(trace_channel, 8, "%s: ASN: %s", ip_addr, geoip_asn);
  }
}

static void set_geoip_value(const char *key, const char *value) {
  int res;

  res = pr_env_set(session.pool, key, value);
  if (res < 0) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "error setting %s environment variable: %s", key, strerror(errno));
  }

  res = pr_table_add_dup(session.notes, pstrdup(session.pool, key),
    (char *) value, 0);
  if (res < 0) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "error adding %s session note: %s", key, strerror(errno));
  }
}

static void set_geoip_values(void) {

  if (geoip_country_code2 != NULL) {
    set_geoip_value("GEOIP_COUNTRY_CODE", geoip_country_code2);
  }

  if (geoip_country_name != NULL) {
    set_geoip_value("GEOIP_COUNTRY_NAME", geoip_country_name);
  }

  if (geoip_region_code != NULL) {
    set_geoip_value("GEOIP_REGION", geoip_region_code);
  }

  if (geoip_region_name != NULL) {
    set_geoip_value("GEOIP_REGION_NAME", geoip_region_name);
  }

  if (geoip_continent_code != NULL) {
    set_geoip_value("GEOIP_CONTINENT_CODE", geoip_continent_code);
  }

  if (geoip_org != NULL) {
    set_geoip_value("GEOIP_ORGANIZATION", geoip_org);
  }

  if (geoip_city != NULL) {
    set_geoip_value("GEOIP_CITY", geoip_city);
  }

  if (geoip_postal_code != NULL) {
    set_geoip_value("GEOIP_POSTAL_CODE", geoip_postal_code);
  }

  if (geoip_latitude != NULL) {
    set_geoip_value("GEOIP_LATITUDE", geoip_latitude);
  }

  if (geoip_longitude != NULL) {
    set_geoip_value("GEOIP_LONGITUDE", geoip_longitude);
  }

  if (geoip_asn != NULL) {
    set_geoip_value("GEOIP_ASN", geoip_asn);
  }

  if (geoip_timezone != NULL) {
    set_geoip_value("GEOIP_TIMEZONE", geoip_timezone);
  }
}

/* Configuration handlers
 */

/* usage:
 *  GeoIPAllowFilter key1 regex1 [key2 regex2 ...]
 *                   sql:/...
 *  GeoIPDenyFilter key1 regex1 [key2 regex2 ...]
 *                  sql:/...
 */
MODRET set_geoipfilter(cmd_rec *cmd) {
#if PR_USE_REGEX
  config_rec *c;
  array_header *deferred_patterns, *filters;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc == 1) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  /* IFF the first parameter starts with "sql:/", then we expect ONLY one
   * parameter.  If not, then we expect an even number of parameters.
   */

  if (strncmp(cmd->argv[1], "sql:/", 5) == 0) {
    if (cmd->argc > 2) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }

  } else {
    if ((cmd->argc-1) % 2 != 0) {
      CONF_ERROR(cmd, "wrong number of parameters");
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  filters = make_array(c->pool, 0, sizeof(struct geoip_filter *));
  deferred_patterns = make_array(c->pool, 0, sizeof(char *));

  if (cmd->argc == 2) {
    const char *pattern;

    pattern = cmd->argv[1];

    /* Advance past the "sql:/" prefix. */
    *((char **) push_array(deferred_patterns)) = pstrdup(c->pool, pattern + 5);

  } else {
    register unsigned int i;

    for (i = 1; i < cmd->argc; i += 2) {
      const char *filter_name, *pattern = NULL;
      struct geoip_filter *filter;

      filter_name = cmd->argv[i];
      pattern = cmd->argv[i+1];

      filter = make_filter(c->pool, filter_name, pattern);
      if (filter == NULL) {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unable to use '",
          filter_name, " ", pattern, "' as filter: ", strerror(errno), NULL));
      }

      *((struct geoip_filter **) push_array(filters)) = filter;
    }
  }

  c->argv[0] = filters;
  c->argv[1] = deferred_patterns;
  return PR_HANDLED(cmd);

#else /* no regular expression support at the moment */
  CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "The ", cmd->argv[0],
    " directive cannot be used on this system, as you do not have POSIX "
    "compliant regex support", NULL));
#endif
}

/* usage: GeoIPEngine on|off */
MODRET set_geoipengine(cmd_rec *cmd) {
  int engine = -1;
  config_rec *c = NULL;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: GeoIPLog path|"none" */
MODRET set_geoiplog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: GeoIPPolicy "allow,deny"|"deny,allow" */
MODRET set_geoippolicy(cmd_rec *cmd) {
  geoip_policy_e policy;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (strcasecmp(cmd->argv[1], "allow,deny") == 0) {
    policy = GEOIP_POLICY_ALLOW_DENY;

  } else if (strcasecmp(cmd->argv[1], "deny,allow") == 0) {
    policy = GEOIP_POLICY_DENY_ALLOW;

  } else {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, ": '", cmd->argv[1],
      "' is not one of the approved GeoIPPolicy settings", NULL));
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(geoip_policy_e));
  *((geoip_policy_e *) c->argv[0]) = policy;

  return PR_HANDLED(cmd);
}

/* usage: GeoIPTable path [flags] */
MODRET set_geoiptable(cmd_rec *cmd) {
  config_rec *c;
  uint32_t flags = 0;
  char *path;

  CHECK_CONF(cmd, CONF_ROOT|CONF_VIRTUAL|CONF_GLOBAL);

  if (cmd->argc < 2) {
    CONF_ERROR(cmd, "wrong number of parameters");
  }

  path = cmd->argv[1];

  if (cmd->argc > 2) {
    register unsigned int i;

    for (i = 2; i < cmd->argc; i++) {
      /* Most of these are ignored, for backward compatibility with the
       * mod_geoip flags.
       */
      if (strcasecmp(cmd->argv[i], "Standard") == 0) {
        /* Ignored. */

      } else if (strcasecmp(cmd->argv[i], "MemoryCache") == 0) {
        /* Ignored. */

      } else if (strcasecmp(cmd->argv[i], "MMapCache") == 0) {
        flags |= MMDB_MODE_MMAP;

      } else if (strcasecmp(cmd->argv[i], "IndexCache") == 0) {
        /* Ignored. */

      } else if (strcasecmp(cmd->argv[i], "CheckCache") == 0) {
        /* Ignored. */

      } else if (strcasecmp(cmd->argv[i], "UTF8") == 0) {
        /* Ignored. */

      } else {
        CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "unknown GeoIPTable flag '",
          cmd->argv[i], "'", NULL));
      }
    }
  }

  c = add_config_param(cmd->argv[0], 2, NULL, NULL);
  c->argv[0] = pstrdup(c->pool, path);
  c->argv[1] = palloc(c->pool, sizeof(uint32_t));
  *((uint32_t *) c->argv[1]) = flags;

  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET geoip2_post_pass(cmd_rec *cmd) {
  int res;

  if (geoip2_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  /* Scan for any deferred GeoIP filters and resolve them. */
  resolve_deferred_filters(cmd->tmp_pool);

  /* Modules such as mod_ifsession may have added new filters; check the
   * filters again.
   */
  res = check_geoip_filters(geoip_policy);
  if (res < 0) {
    const char *user;

    user = pr_table_get(session.notes, "mod_auth.orig-user", NULL);
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "connection from IP %s, user '%s' denied due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr), user);
    pr_log_pri(PR_LOG_NOTICE, MOD_GEOIP2_VERSION
      ": Connection denied from IP %s, user '%s' due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr), user);

    pr_event_generate("mod_geoip.connection-denied", NULL);
    pr_session_disconnect(&geoip2_module, PR_SESS_DISCONNECT_CONFIG_ACL,
      "GeoIP Filters");
  }

  return PR_DECLINED(cmd);
}

/* Event handlers
 */

#if defined(PR_SHARED_MODULE)
static void geoip2_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_geoip2.c", (const char *) event_data) == 0) {
    remove_geoip_tables();
    destroy_pool(geoip2_pool);

    /* Unregister ourselves from all events. */
    pr_event_unregister(&geoip2_module, NULL, NULL);
  }
}
#endif /* PR_SHARED_MODULE */

static void geoip2_postparse_ev(const void *event_data, void *user_data) {
  pr_log_debug(DEBUG8, MOD_GEOIP2_VERSION ": loading static GeoIP tables");
  get_geoip_tables();
}

static void geoip2_restart_ev(const void *event_data, void *user_data) {
  remove_geoip_tables();
  destroy_pool(geoip2_pool);

  geoip2_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(geoip2_pool, MOD_GEOIP2_VERSION);

  geoip2_mmdbs = make_array(geoip2_pool, 0, sizeof(MMDB_s *));
}

/* Initialization functions
 */

static int geoip2_init(void) {

  /* Make sure that mod_geoip is NOT loaded.  If it is, error out.  There
   * can be only one. (Make sure the docs note this, too.)
   */
  if (pr_module_exists("mod_geoip.c") == TRUE) {
    pr_log_pri(PR_LOG_NOTICE, MOD_GEOIP2_VERSION
      ": mod_geoip and mod_geoip2 cannot be used at the same time");
    errno = EPERM;
    return -1;
  }

  geoip2_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(geoip2_pool, MOD_GEOIP2_VERSION);

  geoip2_mmdbs = make_array(geoip2_pool, 0, sizeof(MMDB_s *));

#if defined(PR_SHARED_MODULE)
  pr_event_register(&geoip2_module, "core.module-unload", geoip2_mod_unload_ev,
    NULL);
#endif /* PR_SHARED_MODULE */
  pr_event_register(&geoip2_module, "core.postparse", geoip2_postparse_ev,
    NULL);
  pr_event_register(&geoip2_module, "core.restart", geoip2_restart_ev, NULL);

  pr_log_debug(DEBUG2, MOD_GEOIP2_VERSION ": using libmaxmindb-%s",
    MMDB_lib_version());

  return 0;
}

static int geoip2_sess_init(void) {
  config_rec *c;
  int res;
  pool *tmp_pool;

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPEngine", FALSE);
  if (c != NULL) {
    geoip2_engine = *((int *) c->argv[0]);
  }

  if (geoip2_engine == FALSE) {
    return 0;
  }

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPLog", FALSE);
  if (c != NULL) {
    char *path;

    path = c->argv[0];
    if (strcasecmp(path, "none") != 0) {
      int xerrno;

      pr_signals_block();
      PRIVS_ROOT
      res = pr_log_openfile(path, &geoip2_logfd, PR_LOG_SYSTEM_MODE);
      xerrno = errno;
      PRIVS_RELINQUISH
      pr_signals_unblock();

      if (res < 0) {
        if (res == -1) {
          pr_log_pri(PR_LOG_NOTICE, MOD_GEOIP2_VERSION
            ": notice: unable to open GeoIPLog '%s': %s", path,
            strerror(xerrno));

        } else if (res == PR_LOG_WRITABLE_DIR) {
          pr_log_pri(PR_LOG_WARNING, MOD_GEOIP2_VERSION
            ": notice: unable to open GeoIPLog '%s': parent directory is "
            "world-writable", path);

        } else if (res == PR_LOG_SYMLINK) {
          pr_log_pri(PR_LOG_WARNING, MOD_GEOIP2_VERSION
            ": notice: unable to open GeoIPLog '%s': cannot log to a symlink",
            path);
        }
      }
    }
  }

  tmp_pool = make_sub_pool(geoip2_pool);
  pr_pool_tag(tmp_pool, "GeoIP Session Pool");

  if (geoip2_mmdbs->nelts == 0) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "no usable GeoIPTable files found, skipping GeoIP lookups");

    (void) close(geoip2_logfd);
    destroy_pool(tmp_pool);
    return 0;
  }

  get_geoip_info();

  c = find_config(main_server->conf, CONF_PARAM, "GeoIPPolicy", FALSE);
  if (c != NULL) {
    geoip_policy = *((geoip_policy_e *) c->argv[0]);
  }

  switch (geoip_policy) {
    case GEOIP_POLICY_ALLOW_DENY:
      pr_trace_msg(trace_channel, 8,
        "using policy of allowing connections unless rejected by "
        "GeoIPDenyFilters");
      break;

    case GEOIP_POLICY_DENY_ALLOW:
      pr_trace_msg(trace_channel, 8,
        "using policy of rejecting connections unless allowed by "
        "GeoIPAllowFilters");
      break;
  }

  res = check_geoip_filters(geoip_policy);
  if (res < 0) {
    (void) pr_log_writefile(geoip2_logfd, MOD_GEOIP2_VERSION,
      "connection from IP %s denied due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr));
    pr_log_pri(PR_LOG_NOTICE, MOD_GEOIP2_VERSION
      ": Connection denied from IP %s due to GeoIP filter/policy",
      pr_netaddr_get_ipstr(session.c->remote_addr));

    pr_event_generate("mod_geoip.connection-denied", NULL);

    /* XXX send_geoip_mesg(tmp_pool, mesg) */
    destroy_pool(tmp_pool);

    errno = EACCES;
    return -1;
  }

  set_geoip_values();

  destroy_pool(tmp_pool);
  return 0;
}

/* Module API tables
 */

static conftable geoip2_conftab[] = {
  { "GeoIPAllowFilter",	set_geoipfilter,	NULL },
  { "GeoIPDenyFilter",	set_geoipfilter,	NULL },
  { "GeoIPEngine",	set_geoipengine,	NULL },
  { "GeoIPLog",		set_geoiplog,		NULL },
  { "GeoIPPolicy",	set_geoippolicy,	NULL },
  { "GeoIPTable",	set_geoiptable,		NULL },
  { NULL }
};

static cmdtable geoip2_cmdtab[] = {
  { POST_CMD,	C_PASS,	G_NONE,	geoip2_post_pass,	FALSE, FALSE },
  { 0, NULL },
};

module geoip2_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "geoip2",

  /* Module configuration handler table */
  geoip2_conftab,

  /* Module command handler table */
  geoip2_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  geoip2_init,

  /* Session initialization function */
  geoip2_sess_init,

  /* Module version */
  MOD_GEOIP2_VERSION
};
