#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1


#include "axil-internal.h"

static axil_handler_t *fallback_handlers[FALLBACK_MAX];
static size_t fallback_handlers_len;

static char *env_name(char *key)
{
	static char buf[ENV_KEY_LEN];
	char *b = buf;
	memcpy(b, "HTTP_", 5);
	b += 5;
	for (const char *s = key; *s && (size_t)(b - buf) < sizeof(buf) - 1; s++, b++) {
		if (*s == '-')
			*b = '_';
		else
			*b = (char)toupper((unsigned char)*s);
	}
	*b = '\0';
	return buf;
}

static inline void
headers_get(socket_t fd, size_t *body_start, char *next_lines)
{
	register char *s, *key, *value;

	for (s = next_lines, key = s, value = s; *s;)
		switch (*s) {
		case ':':
			if (value == key) {
				*s = '\0';
				value = (s += 2);
			} else
				s++;
			break;
		case '\r':
			*s = '\0';
			if (s != key) {
				if (s - key >= BUFSIZ)
					*(key + BUFSIZ - 1) = '\0';
				axil_env_put(fd, env_name(key), value);
				key = s += 2;
				value = key;
			} else
				*++s = '\0';

			break;
		default:
			s++;
			break;
		}

	*body_start = s - next_lines;
}

static int request_path_is_safe(const char *target)
{
	char current[BUFSIZ], decoded[BUFSIZ];
	size_t path_len = strcspn(target, "?");

	if (!path_len || path_len >= sizeof(current))
		return 0;
	memcpy(current, target, path_len);
	current[path_len] = '\0';

	for (;;) {
		size_t src = 0, dst = 0;
		int changed = 0;

		while (current[src]) {
			unsigned char c = (unsigned char)current[src++];
			if (c == '%') {
				int hi, lo;

				if (!current[src] || !current[src + 1] ||
				    !isxdigit((unsigned char)current[src]) ||
				    !isxdigit((unsigned char)current[src + 1]))
					return 0;
				hi = isdigit((unsigned char)current[src])
				             ? current[src] - '0'
				             : tolower((unsigned char)
				                               current[src]) -
				                       'a' + 10;
				lo = isdigit((unsigned char)current[src + 1])
				             ? current[src + 1] - '0'
				             : tolower((unsigned char)
				                               current[src +
				                                       1]) -
				                       'a' + 10;
				c = (unsigned char)((hi << 4) | lo);
				src += 2;
				changed = 1;
			}
			if (!c || c == '\\' || c < 0x20 || c == 0x7f)
				return 0;
			decoded[dst++] = (char)c;
		}
		decoded[dst] = '\0';

		for (char *segment = decoded, *p = decoded;; p++) {
			if (*p != '/' && *p)
				continue;
			if (p - segment == 2 && segment[0] == '.' &&
			    segment[1] == '.')
				return 0;
			if (!*p)
				break;
			segment = p + 1;
		}

		if (!changed)
			return decoded[0] == '/';
		memcpy(current, decoded, dst + 1);
	}
}

static char *env_sane(char *str)
{
	static char buf[BUFSIZ];
	char *b;
	for (b = buf;
	     b - buf - 1 < BUFSIZ &&
	     (((unsigned char)*str >= 0x80) || isalnum((unsigned char)*str) ||
	      *str == '/' || *str == '+' || *str == '%' || *str == '&' ||
	      *str == '_' || *str == '-' || *str == ' ' || *str == '=' ||
	      *str == ';' || *str == '.' || *str == '"' || *str == ':' ||
	      *str == ',' || *str == '@' || *str == '~');
	     str++, b++)
		*b = *str;
	*b = '\0';
	return buf;
}

static void
_env_prep(socket_t fd, char *document_uri, char *param, char *method)
{
	char req_content_type[BUFSIZ];

	if (axil_env_get(
	            fd, req_content_type, sizeof(req_content_type),
	            "HTTP_CONTENT_TYPE"))
		strncpy(req_content_type, "text/plain",
		        sizeof(req_content_type));

	axil_env_put(fd, "CONTENT_TYPE", env_sane(req_content_type));
	axil_env_put(fd, "DOCUMENT_URI", document_uri);
	axil_env_put(fd, "QUERY_STRING", env_sane(param));
	axil_env_put(fd, "REQUEST_METHOD", method);
	axil_env_put(
	        fd, "DOCUMENT_ROOT",
#ifdef _WIN32
	        0
#else
	        geteuid()
#endif
	                ? axil_config.chroot
	                : "");
	if (axil_platform && axil_platform->env_prep)
		axil_platform->env_prep(fd);
}

#if defined(_WIN32)
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtime)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)0)
#elif defined(__OpenBSD__)
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtim.tv_sec)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)(sbp)->st_mtim.tv_nsec)
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) ||     \
        defined(__DragonFly__)
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtimespec.tv_sec)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)(sbp)->st_mtimespec.tv_nsec)
#else
#define AXIL_ST_MTIME_SEC(sbp) ((long long)(sbp)->st_mtim.tv_sec)
#define AXIL_ST_MTIME_NSEC(sbp) ((long long)(sbp)->st_mtim.tv_nsec)
#endif

#define AXIL_DEFAULT_CACHE_CONTROL "no-cache"

static void http_date(time_t t, char *out, size_t outlen)
{
	static time_t cached_time = 0;
	static char cached_date[64] = "";

	if (t != 0 && t == cached_time && cached_date[0]) {
		size_t len = strlen(cached_date);
		if (len >= outlen)
			len = outlen - 1;
		memcpy(out, cached_date, len);
		out[len] = '\0';
		return;
	}

	struct tm tm_buf;
	struct tm *tm_info = stl_gmtime_r(&t, &tm_buf);
	if (tm_info) {
		strftime(out, outlen, "%a, %d %b %Y %H:%M:%S GMT", tm_info);
		if (outlen >= sizeof(cached_date)) {
			cached_time = t;
			strncpy(cached_date, out, sizeof(cached_date) - 1);
			cached_date[sizeof(cached_date) - 1] = '\0';
		}
	} else {
		out[0] = '\0';
	}
}

static void static_etag(const struct stat *sb, char *out, size_t outlen)
{
	snprintf(
	        out, outlen, "\"%llx-%llx-%lx-%llx\"",
	        (unsigned long long)sb->st_ino,
	        (unsigned long long)AXIL_ST_MTIME_SEC(sb),
	        (unsigned long)AXIL_ST_MTIME_NSEC(sb),
	        (unsigned long long)sb->st_size);
}

static int month_eq(const char *a, const char *b)
{
	int i;
	for (i = 0; i < 3; i++) {
		char ca = a[i], cb = b[i];
		if (ca >= 'A' && ca <= 'Z')
			ca = (char)(ca + ('a' - 'A'));
		if (cb >= 'A' && cb <= 'Z')
			cb = (char)(cb + ('a' - 'A'));
		if (ca != cb)
			return 0;
	}
	return 1;
}

static int month_number(const char *mon)
{
	static const char *const names[] = { "Jan", "Feb", "Mar", "Apr",
		                             "May", "Jun", "Jul", "Aug",
		                             "Sep", "Oct", "Nov", "Dec" };
	int i;
	for (i = 0; i < 12; i++)
		if (month_eq(mon, names[i]))
			return i;
	return -1;
}

static time_t tm_to_time_t_utc(const struct tm *t)
{
	long long y = (long long)t->tm_year + 1900;
	int m = t->tm_mon + 1;
	long long era;
	long long days;
	unsigned yoe, doy, doe;

	if (m <= 2)
		y--;
	era = (y >= 0 ? y : y - 399) / 400;
	yoe = (unsigned)(y - era * 400);
	doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + (unsigned)t->tm_mday - 1;
	doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
	days = era * 146097 + (long long)doe - 719468;

	return (time_t)(days * 86400) + t->tm_hour * 3600 + t->tm_min * 60 +
	       t->tm_sec;
}

static int http_date_parse(const char *s, time_t *out)
{
	char wday[4], mon[4];
	int day, year, hh, mm, ss;
	int m;
	struct tm tm_info;

	if (!s || sscanf(s, "%3[A-Za-z], %d %3[A-Za-z] %d %d:%d:%d GMT", wday,
	                 &day, mon, &year, &hh, &mm, &ss) != 7)
		return -1;

	m = month_number(mon);
	if (m < 0)
		return -1;

	memset(&tm_info, 0, sizeof(tm_info));
	tm_info.tm_year = year - 1900;
	tm_info.tm_mon = m;
	tm_info.tm_mday = day;
	tm_info.tm_hour = hh;
	tm_info.tm_min = mm;
	tm_info.tm_sec = ss;

	*out = tm_to_time_t_utc(&tm_info);
	return 0;
}

static void static_validator_headers(
        const char *etag, const char *last_mod, const char *cache_ctl,
        char *out, size_t outlen)
{
	char etag_hdr[80] = "";
	char last_mod_hdr[100] = "";
	char cache_hdr[256] = "";

	if (etag && *etag)
		snprintf(etag_hdr, sizeof(etag_hdr), "ETag: %s\r\n", etag);
	if (last_mod && *last_mod)
		snprintf(
		        last_mod_hdr, sizeof(last_mod_hdr),
		        "Last-Modified: %s\r\n", last_mod);
	if (cache_ctl && *cache_ctl)
		snprintf(
		        cache_hdr, sizeof(cache_hdr), "Cache-Control: %s\r\n",
		        cache_ctl);

	snprintf(out, outlen, "%s%s%s", etag_hdr, last_mod_hdr, cache_hdr);
}

static void static_cache_control(const char *uri, char *out, size_t outlen)
{
	if (axil_platform && axil_platform->cache_policy &&
	    axil_platform->cache_policy(uri, out, outlen))
		return;
	snprintf(out, outlen, "%s", AXIL_DEFAULT_CACHE_CONTROL);
}

static inline int static_not_modified(
        socket_t fd, const char *etag, const char *last_mod,
        const char *cache_ctl)
{
	struct descr *d = &descr_map[fd];
	char vhdr[512];
	char date[100];

	http_date(time(NULL), date, sizeof(date));
	static_validator_headers(etag, last_mod, cache_ctl, vhdr, sizeof(vhdr));

	d->flags |= DF_TO_CLOSE;
	axil_writef(
	        fd,
	        "HTTP/1.1 304 Not Modified\r\n"
	        "Date: %s\r\n"
	        "Server: axil/0.0.1 (Unix)\r\n"
	        "%s" AXIL_CROSS_ORIGIN_HEADERS "\r\n",
	        date, vhdr);
	if (!d->remaining_len)
		axil_close(fd);
	return 1;
}

static void static_write(
        socket_t fd, char *status, const char *content_type, int want_fd,
        off_t total, const char *etag, const char *last_mod,
        const char *cache_ctl)
{
	struct descr *d = &descr_map[fd];
	char date[100];
	char vhdr[512];

	http_date(time(NULL), date, sizeof(date));
	static_validator_headers(etag, last_mod, cache_ctl, vhdr, sizeof(vhdr));

	char hdr[1024];
	int hlen = snprintf(
	        hdr, sizeof(hdr),
	        "HTTP/1.1 %s\r\n"
	        "Date: %s\r\n"
	        "Server: axil/0.0.1 (Unix)\r\n"
	        "Content-Length: %lu\r\n"
	        "Content-Type: %s\r\n"
	        "%s" AXIL_CROSS_ORIGIN_HEADERS "\r\n",
	        status, date, (unsigned long)total, content_type, vhdr);

	if (d->flags & DF_HEAD) {
		if (hlen > 0)
			axil_write(fd, hdr, (size_t)hlen);
		if (want_fd > 0)
			close(want_fd);
		goto end;
	}

	if (want_fd <= 0) {
		if (hlen > 0)
			axil_write(fd, hdr, (size_t)hlen);
		axil_writef(fd, "%s\r\n", status);
		goto end;
	}

	// static file: read into buffer and combine with headers if it fits in 64KB
	char b[BUFSIZ * 16];
	ssize_t first_len = read(want_fd, b, sizeof(b));
	if (first_len > 0) {
		if (hlen > 0 && (size_t)hlen + (size_t)first_len <= sizeof(b)) {
			char combined[sizeof(b) + sizeof(hdr)];
			memcpy(combined, hdr, (size_t)hlen);
			memcpy(combined + hlen, b, (size_t)first_len);
			axil_write(fd, combined, (size_t)hlen + (size_t)first_len);
		} else {
			if (hlen > 0)
				axil_write(fd, hdr, (size_t)hlen);
			axil_write(fd, b, (size_t)first_len);
		}

		ssize_t len;
		while ((len = read(want_fd, b, sizeof(b))) > 0)
			axil_write(fd, b, len);
	} else if (hlen > 0) {
		axil_write(fd, hdr, (size_t)hlen);
	}

	close(want_fd);

end:
	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		axil_close(fd);
}

/* RFC 7232 3.2: If-None-Match may be "*" or a comma-separated list of
 * entity-tags. Return 1 when the value matches the strong etag. */
static int static_etag_matches(const char *inm, const char *etag)
{
	const char *p, *q;
	size_t len;

	if (strcmp(inm, "*") == 0)
		return 1;

	p = inm;
	len = strlen(etag);
	while (*p) {
		while (*p == ' ' || *p == '\t' || *p == ',')
			p++;
		if (!*p)
			break;
		q = p;
		while (*q && *q != ',')
			q++;
		while (q > p && (q[-1] == ' ' || q[-1] == '\t'))
			q--;
		if ((size_t)(q - p) == len && strncmp(p, etag, len) == 0)
			return 1;
		p = q;
	}
	return 0;
}

static inline int
request_handle_static(socket_t fd, char *document_uri, struct stat *stat_buf)
{
	char buf[BUFSIZ];
	char etag[64];
	char last_mod[100];
	char cache_ctl[256];
	char inm[64] = { 0 };
	char ims[64] = { 0 };
	time_t ims_time;
	errno = 0;
	char *ext, *s;
	const char *content_type;

	if (document_uri[strlen(document_uri) - 1] == '/') {
		snprintf(buf, sizeof(buf), "%sindex.html", document_uri);
		document_uri = buf;
	}

	char *filename = NULL;
	if (axil_platform && axil_platform->static_allowed)
		filename =
		        axil_platform->static_allowed(document_uri, stat_buf);

	if (!filename)
		return 0;
	if (!S_ISREG(stat_buf->st_mode))
		return 0;

	ext = filename;
	for (s = ext; *s; s++)
		if (*s == '.')
			ext = s + 1;

	content_type = "application/octet-stream";
	if (ext) {
		const void *skey = corm_get(mime_hd, ext);
		if (skey)
			content_type = skey;
	}

	static_etag(stat_buf, etag, sizeof(etag));
	http_date(stat_buf->st_mtime, last_mod, sizeof(last_mod));
	static_cache_control(document_uri, cache_ctl, sizeof(cache_ctl));

	/* RFC 7232 6: If-None-Match takes precedence over If-Modified-Since. */
	if (axil_header_get(fd, "If-None-Match", inm, sizeof(inm)) == 0) {
		if (static_etag_matches(inm, etag))
			return static_not_modified(
			        fd, etag, last_mod, cache_ctl);
	} else if (
	        axil_header_get(fd, "If-Modified-Since", ims, sizeof(ims)) ==
	                0 &&
	        http_date_parse(ims, &ims_time) == 0 &&
	        stat_buf->st_mtime <= ims_time)
	{
		return static_not_modified(fd, etag, last_mod, cache_ctl);
	}

	static_write(
	        fd, "200 OK", content_type, open(filename, O_RDONLY),
	        stat_buf->st_size, etag, last_mod, cache_ctl);

	return 1;
}

static inline int request_handle_redirect(socket_t fd, char *document_uri)
{
	struct descr *d = &descr_map[fd];

	if ((axil_srv_flags & AXIL_SSL_ONLY) && (axil_srv_flags & AXIL_SSL) &&
	    !d->cSSL)
	{
		char host[ENV_KEY_LEN] = { 0 };
		axil_env_get(fd, host, sizeof(host), "HTTP_HOST");
		char response[8285];
		d->flags |= DF_TO_CLOSE;

		snprintf(
		        response, sizeof(response),
		        "HTTP/1.1 301 Moved Permanently\r\n"
		        "Location: https://%s%s\r\n"
		        "Content-Length: 0\r\n"
		        "Connection: close\r\n"
		        "\r\n",
		        host, document_uri);
		axil_writef(fd, "%s", response);

		if (!d->remaining_len)
			axil_close(fd);

		return 1;
	}

	return 0;
}

// Generates and sends an HTML directory listing.
static inline void
request_handle_autoindex(socket_t fd, const char *uri_path, const char *fs_path)
{
	size_t body_cap = BUFSIZ * 8;
	char *body;
	char line[BUFSIZ * 2];
	size_t body_len = 0;
	DIR *dir;
	struct dirent *entry;

	dir = opendir(fs_path);
	if (!dir) {
		static_write(
		        fd, "500 Internal Server Error", "text/plain", -1, 27,
		        "", "", "");
		return;
	}

	body = calloc(1, body_cap);
	if (!body) {
		closedir(dir);
		static_write(
		        fd, "500 Internal Server Error", "text/plain", -1, 27,
		        "", "", "");
		return;
	}

	// Start building the HTML body
	body_len = (size_t)snprintf(
	        body, body_cap,
	        "<!DOCTYPE html><html><head><title>Index of %s</title></head>"
	        "<body><h1>Index of %s</h1><hr><pre>",
	        uri_path, uri_path);

	while ((entry = readdir(dir)) != NULL) {
		size_t line_len;

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		line_len = (size_t)snprintf(
		        line, sizeof(line), "<a href=\"./%s\">%s</a>\n",
		        entry->d_name, entry->d_name);
		if (line_len >= sizeof(line))
			continue;

		if (body_len + line_len + 32 >= body_cap) {
			size_t new_cap = body_cap * 2;
			char *grown = realloc(body, new_cap);
			if (!grown)
				break;
			body = grown;
			body_cap = new_cap;
		}

		memcpy(body + body_len, line, line_len + 1);
		body_len += line_len;
	}
	closedir(dir);

	memcpy(body + body_len, "</pre><hr></body></html>", 25);
	body_len += 24;

	// Write HTTP headers and the generated body
	time_t now = time(NULL);
	struct tm *tm_info = gmtime(&now);
	char date[100];
	strftime(date, sizeof(date), "%a, %d %b %Y %H:%M:%S GMT", tm_info);

	axil_writef(
	        fd,
	        "HTTP/1.1 200 OK\r\n"
	        "Date: %s\r\n"
	        "Server: axil/0.0.1 (Unix)\r\n"
	        "Content-Length: %lu\r\n"
	        "Content-Type: text/html\r\n"
	        "Connection: close\r\n" AXIL_CROSS_ORIGIN_HEADERS "\r\n",
	        date, body_len);
	axil_write(fd, body, body_len);
	free(body);

	struct descr *d = &descr_map[fd];
	if ((d->flags & DF_TO_CLOSE) && !d->remaining_len)
		axil_close(fd);
}

typedef struct {
	char env_key[256];
	char value[256];
} axil_pattern_param_t;

typedef struct {
	int matched;
	int literal_chars;
	int param_count;
	int wildcard_count;
	int param_used;
	axil_pattern_param_t params[16];
} axil_pattern_match_t;

static void
pattern_commit_params(socket_t fd, const axil_pattern_match_t *match)
{
	int i;

	for (i = 0; i < match->param_used; i++)
		axil_env_put(
		        fd, (char *)match->params[i].env_key,
		        (char *)match->params[i].value);
}

static int pattern_better_match(
        const axil_pattern_match_t *candidate, const axil_pattern_match_t *best)
{
	if (!best->matched)
		return 1;

	if (candidate->wildcard_count != best->wildcard_count)
		return candidate->wildcard_count < best->wildcard_count;

	if (candidate->literal_chars != best->literal_chars)
		return candidate->literal_chars > best->literal_chars;

	if (candidate->param_count != best->param_count)
		return candidate->param_count < best->param_count;

	return 0;
}

/* Match a URL pattern against a path.
 * Supports:
 *   - :param single-segment captures
 *   - terminal * catch-alls (e.g. "/sb/" followed by "*")
 *   - optional trailing slash on either the pattern or the path
 */
static int
pattern_match(const char *pat, const char *path, axil_pattern_match_t *m)
{
	memset(m, 0, sizeof(*m));

	for (;;) {
		/* skip redundant trailing slashes */
		while (*pat == '/' &&
		       (pat[1] == '/' || !pat[1] || pat[1] == '?'))
			pat++;

		while (*path == '/' &&
		       (path[1] == '/' || !path[1] || path[1] == '?'))
			path++;

		/* both done */
		if ((!*pat || *pat == '?') && (!*path || *path == '?')) {
			m->matched = 1;
			return 1;
		}

		/* one ended early */
		if (!*pat || !*path || *pat == '?' || *path == '?')
			return 0;

		/* wildcard */
		if (*pat == '*' &&
		    (!pat[1] || pat[1] == '?' ||
		     (pat[1] == '/' && (!pat[2] || pat[2] == '?'))))
		{
			m->wildcard_count++;
			m->matched = 1;
			return 1;
		}

		/* consume slash */
		if (*pat == '/' || *path == '/') {
			if (*pat != *path)
				return 0;
			pat++;
			path++;
			continue;
		}

		const char *ps = pat;
		const char *us = path;

		while (*pat && *pat != '/' && *pat != '?')
			pat++;

		while (*path && *path != '/' && *path != '?')
			path++;

		size_t plen = pat - ps;
		size_t ulen = path - us;

		/* parameter */
		if (*ps == ':') {
			if (!ulen)
				return 0;

			if (m->param_used >=
			    (int)(sizeof(m->params) / sizeof(m->params[0])))
				return 0;

			axil_pattern_param_t *pp = &m->params[m->param_used++];

			size_t k = snprintf(
			        pp->env_key, sizeof(pp->env_key),
			        "PATTERN_PARAM_");

			for (size_t i = 1;
			     i < plen && k + 1 < sizeof(pp->env_key); i++)
				pp->env_key[k++] =
				        toupper((unsigned char)ps[i]);

			pp->env_key[k] = 0;

			if (ulen >= sizeof(pp->value))
				return 0;

			memcpy(pp->value, us, ulen);
			pp->value[ulen] = 0;

			m->param_count++;
			continue;
		}

		/* literal */
		if (plen != ulen || memcmp(ps, us, plen))
			return 0;

		m->literal_chars += plen;
	}
}

/* Pattern matching for registered handlers
 * Supports :param syntax (e.g., "/chords/:id")
 * Sets PATTERN_PARAM_* env vars for matched parameters
 */
static axil_handler_t *axil_match_pattern(
        const char *path_with_method, const char *document_uri, socket_t fd)
{
	/* Iterate through all registered handlers */
	uint32_t cur = corm_iter(hdlr_hd, NULL, 0);
	const void *pattern_key;
	const void *handler_ptr;
	axil_handler_t *best_handler = NULL;
	axil_pattern_match_t best_match;

	memset(&best_match, 0, sizeof(best_match));

	while (corm_next(&pattern_key, &handler_ptr, cur)) {
		const char *pattern = (const char *)pattern_key;
		axil_pattern_match_t candidate;
		int matched = 0;

		/* Skip non-patterns (no special path syntax) */
		if (!strchr(pattern, ':') && !strchr(pattern, '*'))
			continue;

		memset(&candidate, 0, sizeof(candidate));
		if (pattern_match(pattern, path_with_method, &candidate))
			matched = 1;
		else if (pattern_match(pattern, document_uri, &candidate))
			matched = 1;

		if (matched && pattern_better_match(&candidate, &best_match)) {
			memcpy(&best_handler, handler_ptr,
			       sizeof(best_handler));
			best_match = candidate;
		}
	}

	corm_fin(cur);

	if (!best_handler)
		return NULL;

	pattern_commit_params(fd, &best_match);
	return best_handler;
}

/* Sleep for the given number of microseconds. select() with a zero descriptor
 * count is the portable POSIX sleep; winsock rejects NULL sets, so it gets
 * Sleep() instead. usleep() is not portable (and is gone from some systems). */
static void axil_msleep(unsigned us)
{
#ifdef _WIN32
	Sleep((us + 999) / 1000);
#else
	struct timeval tv;

	tv.tv_sec = us / 1000000;
	tv.tv_usec = us % 1000000;
	select(0, NULL, NULL, NULL, &tv);
#endif
}

/* Ensures the full POST body is present in the global `input` buffer.
 * Returns 0 on success, -1 if the request was rejected (caller must return). */
static int
buffer_post_body(socket_t fd, int argc, char *argv[], size_t body_start)
{
	char clen_str[32] = { 0 };
	axil_env_get(fd, clen_str, sizeof(clen_str), "HTTP_CONTENT_LENGTH");
	if (!clen_str[0])
		return 0;

	size_t content_length = strtoul(clen_str, NULL, 10);
	size_t limit = axil_config.max_body_size ? axil_config.max_body_size
	                                         : AXIL_DEFAULT_MAX_BODY_SIZE;

	if (content_length > limit) {
		axil_header_set(fd, "Connection", "close");
		axil_set_flags(fd, DF_TO_CLOSE);
		axil_respond(fd, 413, "");
		return -1;
	}

	size_t headers_offset = (size_t)(argv[argc] - (char *)input);
	size_t needed = headers_offset + body_start + 1 + content_length;
	struct io *dio = &io[fd];

	/* A non-blocking socket may simply not have the rest of the body yet,
	 * which used to be indistinguishable from a disconnect and killed the
	 * request. Retry EAGAIN a bounded number of times: this runs inline on the
	 * event loop, so it cannot wait indefinitely. A real EOF or error still
	 * fails immediately.
	 *
	 * Only stalls count against the budget. Counting every read would cap
	 * the body at 20 * BUFSIZ (~160 KiB) and silently truncate anything
	 * bigger, since falling out of the loop used to return 0. The worst case
	 * cost to the event loop stays 20 * 500 us = 10 ms; a handler that must
	 * not block at all wants axil_respond_defer() instead. */
	for (int stalls = 0; input_len < needed;) {
		char buf[BUFSIZ];
		ssize_t n = dio->read(fd, buf, sizeof(buf), 0);
		if (n == 0) {
			/* Client disconnected or lied about Content-Length */
			axil_close(fd);
			return -1;
		}
		if (n < 0) {
			if ((errno == EAGAIN || errno == EWOULDBLOCK) &&
			    stalls < MAX_BODY_STALL_RETRIES) {
				stalls++;
				axil_msleep(BODY_STALL_SLEEP_MS);
				continue;
			}
			axil_close(fd);
			return -1;
		}
		if (input_len + (size_t)n > input_size) {
			char *old_base = (char *)input;
			size_t old_size = input_size;
			input_size = (input_len + (size_t)n) * 2;
			input = realloc(input, input_size);
			if (!input) {
				input = (unsigned char *)old_base;
				input_size = old_size;
				axil_close(fd);
				return -1;
			}
			ptrdiff_t shift = (char *)input - old_base;
			for (int i = 0; i <= argc; i++)
				argv[i] += shift;
		}
		memcpy(input + input_len, buf, n);
		input_len += (size_t)n;
	}

	/* The handler only gets a bare `char *` (axil_handler_t): no length
	 * argument, and axil exposes no content-length accessor, so strlen(body) is
	 * the only length it can obtain. Terminate at the *declared* end, not at
	 * input_len: a read never stops at Content-Length, so terminating there
	 * would hand the handler whatever the final read overshot with. Those extra
	 * bytes cost nothing to discard, since axil closes after every response.
	 *
	 * In bounds: the loop above exits only once input_len >= needed, and needed
	 * is exactly this offset, so body_end <= input_len. axil_read() keeps
	 * input_len < input_size, and the realloc above grows with room to spare. */
	size_t body_end = headers_offset + body_start + 1 + content_length;

	input[body_end] = '\0';

	return 0;
}

static inline int request_handle_trailing_slash(socket_t fd, char *document_uri)
{
	struct stat stat_buf;
	int uri_len = strlen(document_uri);

	if (uri_len > 1 && document_uri[uri_len - 1] != '/') {
		char *fs_path = NULL;
		if (axil_platform && axil_platform->static_allowed)
			fs_path = axil_platform->static_allowed(
			        document_uri, &stat_buf);

		if (fs_path && S_ISDIR(stat_buf.st_mode)) {
			struct descr *d = &descr_map[fd];
			char host[ENV_KEY_LEN] = { 0 };
			axil_env_get(fd, host, sizeof(host), "HTTP_HOST");
			const char *scheme = d->cSSL ? "https" : "http";

			axil_writef(
			        fd,
			        "HTTP/1.1 301 Moved Permanently\r\n"
			        "Location: %s://%s%s/\r\n"
			        "Content-Length: 0\r\n"
			        "Connection: close\r\n"
			        "\r\n",
			        scheme, host, document_uri);

			d->flags |= DF_TO_CLOSE;
			if (!d->remaining_len)
				axil_close(fd);
			return 1;
		}
	}

	return 0;
}

static void request_handle(socket_t fd, int argc, char *argv[], int req_flags)
{
	char *method;
	struct descr *d = &descr_map[fd];
	size_t body_start;
	char document_uri[BUFSIZ], *param;
	struct stat stat_buf;

	if (req_flags & AXIL_POST)
		method = "POST";
	else if (req_flags & AXIL_PUT)
		method = "PUT";
	else if (req_flags & AXIL_DELETE)
		method = "DELETE";
	else if (req_flags & AXIL_HEAD) {
		method = "HEAD";
		d->flags |= DF_HEAD;
	} else
		method = "GET";

	char ipstr[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &d->addr.sin_addr, ipstr, sizeof(ipstr));
	WARN("%d (%s) %s %s\n", fd, ipstr, method, argv[1]);

	if (argc < 2 || !request_path_is_safe(argv[1])) {
		axil_close(fd);
		return;
	}

	size_t target_len = strlen(argv[1]);
	if (target_len >= sizeof(document_uri)) {
		axil_respond(fd, 414, "URI Too Long");
		axil_close(fd);
		return;
	}
	size_t decoded_len = axil_url_decode(
	        argv[1], target_len, document_uri, sizeof(document_uri));
	if (memchr(document_uri, '\0', decoded_len)) {
		axil_close(fd);
		return;
	}

	param = strchr(document_uri, '?');
	if (param)
		*param++ = '\0';
	else
		param = "";

	headers_get(fd, &body_start, argv[argc]);

	/* For requests with Content-Length (POST/PUT/DELETE), ensure full body is buffered.
	 * axil_read() may return after reading only the headers if the body
	 * arrives in a separate TCP segment. */
	if (req_flags & (AXIL_POST | AXIL_PUT | AXIL_DELETE)) {
		if (buffer_post_body(fd, argc, argv, body_start) < 0)
			return;
	}

	if (axil_platform && axil_platform->auth_try)
		axil_platform->auth_try(fd);

	if (request_handle_trailing_slash(fd, document_uri))
		return;

	/* Check for registered websocket handler before auto-detection */
	char path_with_method[16384];
	snprintf(
	        path_with_method, sizeof(path_with_method), "%s:%s", method,
	        document_uri);
	const void *ws_key = corm_get(ws_hd, path_with_method);
	if (!ws_key)
		ws_key = corm_get(ws_hd, document_uri);

	axil_ws_upstream_t *ws_handler = NULL;
	if (ws_key) {
		memcpy(&ws_handler, ws_key, sizeof(ws_handler));
	}

	/* Prepare environment for handlers */
	char *body = argv[argc] + body_start + 1;
	_env_prep(fd, document_uri, param, method);

	/* If websocket handler registered, call it */
	if (ws_handler) {
		socket_t upstream = ws_handler(fd);
		if (upstream != INVALID_SOCKET) {
#ifndef _WIN32
			int upfl = fcntl(upstream, F_GETFL, 0);
			if (upfl != -1)
				fcntl(upstream, F_SETFL, upfl | O_NONBLOCK);
#endif

			char ws_key[128];
			if (axil_env_get(
			            fd, ws_key, sizeof(ws_key),
			            "HTTP_SEC_WEBSOCKET_KEY"))
			{
				fprintf(stderr,
				        "WS: no Sec-WebSocket-Key header\n");
				axil_sock_close(upstream);
			} else {
				char req_buf[2048];
				int len = snprintf(
				        req_buf, sizeof(req_buf),
				        "%s %s HTTP/1.1\r\n"
				        "Host: 127.0.0.1:3000\r\n"
				        "Upgrade: websocket\r\n"
				        "Connection: Upgrade\r\n"
				        "Sec-WebSocket-Key: %s\r\n"
				        "Sec-WebSocket-Version: 13\r\n"
				        "\r\n",
				        argv[0], argv[1], ws_key);

				if (len <= 0 || len >= (int)sizeof(req_buf)) {
					axil_sock_close(upstream);
					return;
				}

				if (upstream >= FD_SETSIZE) {
					axil_sock_close(upstream);
					return;
				}

				axil_upstream_descr_init(upstream);

				tunnel_pair[fd] = upstream;
				tunnel_pair[upstream] = fd;

				/* both ends belong to the same pending WS proxy
				 * pair */
				descr_map[fd].flags |= DF_WS_PROXY_PENDING;
				descr_map[upstream].flags |=
				        DF_WS_WAITING | DF_WS_PROXY_PENDING;

				FD_SET(upstream, &fds_active);

#ifdef MSG_NOSIGNAL
				ssize_t wr = send(
				        upstream, req_buf, len, MSG_NOSIGNAL);
#else
				ssize_t wr = write(upstream, req_buf, len);
#endif
				if (wr < 0 || wr < len) {
					axil_tunnel_close_raw(upstream);
				}
			}
		}
		return;
	}

	if (!(d->flags & DF_WEBSOCKET))
		d->flags |= DF_TO_CLOSE;

	if (request_handle_static(fd, document_uri, &stat_buf))
		return;

	char *autoindex_path = NULL;
	if (axil_platform && axil_platform->autoindex_allowed)
		autoindex_path = axil_platform->autoindex_allowed(
		        document_uri, &stat_buf);
	if (autoindex_path) {
		request_handle_autoindex(fd, document_uri, autoindex_path);
		return;
	}

	if (request_handle_redirect(fd, document_uri))
		return;

	/* Try HTTP handler match */
	const void *key = corm_get(hdlr_hd, path_with_method);
	if (!key && (req_flags & AXIL_HEAD)) {
		char get_path[16384];
		snprintf(get_path, sizeof(get_path), "GET:%s", document_uri);
		key = corm_get(hdlr_hd, get_path);
	}
	if (!key)
		key = corm_get(hdlr_hd, document_uri);

	axil_handler_t *hdlr = NULL;
	if (key) {
		memcpy(&hdlr, key, sizeof(hdlr));
	} else {
		/* Try pattern matching */
		hdlr = axil_match_pattern(path_with_method, document_uri, fd);
		if (!hdlr && (req_flags & AXIL_HEAD)) {
			char get_path[16384];
			snprintf(get_path, sizeof(get_path), "GET:%s", document_uri);
			hdlr = axil_match_pattern(get_path, document_uri, fd);
		}
	}

	if (hdlr) {
		hdlr(fd, body);
		return;
	}

	if (axil_config.default_handler) {
		axil_config.default_handler(fd, body);
		return;
	}

	for (size_t i = 0; i < fallback_handlers_len; i++) {
		if (fallback_handlers[i](fd, body))
			return;
	}

	axil_respond(fd, 404, "404 Not Found\n");
}

void axil_register_handler(char *path, axil_handler_t handler)
{
	corm_put(hdlr_hd, path, &handler);
}

int axil_register_fallback_handler(axil_handler_t handler)
{
	if (fallback_handlers_len >= FALLBACK_MAX)
		return -1;

	fallback_handlers[fallback_handlers_len++] = handler;
	return 0;
}

void axil_ws_handler(char *path, axil_ws_upstream_t handler)
{
	corm_put(ws_hd, path, &handler);
}

/* Apply -A in the library, not only in the axil executable's weak
 * axil_connect(). Library-linked hosts otherwise upgrade without any provenance
 * mark, even though DF_AUTH_AUTO is the only thing that distinguishes a
 * published server identity from a proven one. Idempotent: callers and the
 * executable's axil_connect() may both run it for the same descriptor. */
static void
axil_autoauth_apply(socket_t fd)
{
	if (!(axil_config.flags & AXIL_AUTOAUTH))
		return;

#ifndef _WIN32
	struct passwd *pw = getpwuid(geteuid());
	axil_auth(fd, pw ? pw->pw_name : "root");
#else
	axil_auth(fd, "root");
#endif

	if (FD_VALID(fd))
		axil_set_flags(fd, axil_flags(fd) | DF_AUTH_AUTO);
}

int axil_ws_upgrade(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	char buf[ENV_VALUE_LEN];

	if (d->flags & DF_WEBSOCKET)
		return 0;

	if (axil_env_get(fd, buf, sizeof(buf), "HTTP_SEC_WEBSOCKET_KEY"))
		return -1;

	struct io *dio = &io[fd];
	if (ws_init(fd, buf))
		return -1;

	d->flags |= DF_WEBSOCKET;
	dio->read = ws_read;
	dio->write = ws_write;

	axil_autoauth_apply(fd);
	if (!axil_connect || axil_connect(fd))
		d->flags |= DF_CONNECTED;

	return 0;
}

int axil_ws_write(socket_t fd, const void *data, size_t len)
{
	return ws_write(fd, (void *)data, len, 0);
}

ssize_t axil_ws_read(socket_t fd, void *buf, size_t len)
{
	return ws_read(fd, buf, len, 0);
}

int axil_ws_close(socket_t fd)
{
	/* ws_close() is void and cannot report this, so the bound is checked here
	 * as well as inside ws_close_status(): the other three wrappers get it for
	 * free because the functions they call return int. Without it, -1 from a
	 * failed accept reached io[cfd].lower_write and frame_map[cfd]. */
	if (!FD_VALID(fd)) {
		errno = EBADF;
		return -1;
	}
	ws_close(fd);
	return 0;
}

int axil_ws_printf(socket_t fd, const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	int ret = ws_dprintf(fd, fmt, args);
	va_end(args);
	return ret;
}

void axil_ws_tunnel(socket_t a, socket_t b)
{
	struct descr *da = &descr_map[a];
	struct descr *db = &descr_map[b];

#ifndef _WIN32
	int afl = fcntl(a, F_GETFL, 0), bfl = fcntl(b, F_GETFL, 0);
	if (afl != -1)
		fcntl(a, F_SETFL, afl | O_NONBLOCK);
	if (bfl != -1)
		fcntl(b, F_SETFL, bfl | O_NONBLOCK);
#endif

	FD_SET(a, &fds_active);
	FD_SET(b, &fds_active);

	da->flags &= ~(DF_WS_WAITING | DF_WS_PROXY_PENDING);
	db->flags &= ~(DF_WS_WAITING | DF_WS_PROXY_PENDING);

	da->flags |= DF_TUNNEL;
	db->flags |= DF_TUNNEL;

	tunnel_pair[a] = b;
	tunnel_pair[b] = a;
}

void do_GET(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, 0);
	corm_drop(query_db);
}

void do_HEAD(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_HEAD);
	corm_drop(query_db);
}

void do_POST(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_POST);
	corm_drop(query_db);
}

void do_PUT(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_PUT);
	corm_drop(query_db);
}

void do_DELETE(socket_t fd, int argc, char *argv[])
{
	request_handle(fd, argc, argv, AXIL_DELETE);
	corm_drop(query_db);
}

int axil_respond_file(socket_t fd, const char *path, const char *allowed_exts)
{
	char len_buf[32];
	const char *ext = NULL;
	const char *mime = NULL;
	FILE *fp;
	struct stat st;
	char *buf;
	const char *filename;

	if (!path || !path[0]) {
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}

	filename = strrchr(path, '/');
	filename = filename ? filename + 1 : path;

	ext = strrchr(filename, '.');
	if (!ext || !ext[1]) {
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}
	ext++; /* skip '.' */

	if (mime_hd) {
		const void *val = corm_get(mime_hd, ext);
		if (val)
			mime = (const char *)val;
	}
	if (!mime)
		mime = "application/octet-stream";

	if (allowed_exts && allowed_exts[0]) {
		if (!strstr(allowed_exts, ext)) {
			axil_respond_plain(fd, 404, "Not found");
			return -1;
		}
	}

	fp = fopen(path, "rb");
	if (!fp) {
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}
	if (fstat(fileno(fp), &st) != 0 || !S_ISREG(st.st_mode) ||
	    st.st_size < 0)
	{
		fclose(fp);
		axil_respond_plain(fd, 404, "Not found");
		return -1;
	}

	if (st.st_size == 0) {
		fclose(fp);
		axil_header_set(fd, "Content-Type", mime);
		axil_header_set(fd, "Content-Length", "0");
		axil_respond(fd, 200, "");
		return 0;
	}

	buf = malloc((size_t)st.st_size);
	if (!buf) {
		fclose(fp);
		axil_respond_plain(fd, 500, "Internal server error");
		return -1;
	}
	if (fread(buf, 1, (size_t)st.st_size, fp) != (size_t)st.st_size) {
		fclose(fp);
		free(buf);
		axil_respond_plain(fd, 500, "Short read");
		return -1;
	}
	fclose(fp);

	snprintf(len_buf, sizeof(len_buf), "%ld", (long)st.st_size);
	axil_header_set(fd, "Content-Type", mime);
	axil_header_set(fd, "Content-Length", len_buf);

	/* The body must be queued between respond_defer() and
	 * respond_defer_done(). Passing NULL to axil_respond() instead sends the
	 * headers as their own deferred response, so the body that follows is
	 * dropped and the client sees a truncated 0-byte file. */
	void *defer = axil_respond_defer(fd, 200);
	if (!defer) {
		free(buf);
		return -1;
	}
	if (!(descr_map[fd].flags & DF_HEAD))
		axil_write(fd, buf, (size_t)st.st_size);
	free(buf);
	axil_respond_defer_done(defer);
	return 0;
}
