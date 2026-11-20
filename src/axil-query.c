#define _XOPEN_SOURCE 700
#define _DARWIN_C_SOURCE 1
#define _DEFAULT_SOURCE 1
#define _GNU_SOURCE 1


#include "axil-internal.h"

void axil_env_clear(socket_t fd)
{
	struct descr *d = &descr_map[fd];
	if (d->env_hd)
		corm_drop(d->env_hd);

	d->resp_headers[0] = '\0';
}

unsigned axil_env(socket_t fd)
{
	return descr_map[fd].env_hd;
}

void axil_header_set(socket_t fd, const char *key, const char *value)
{
	struct descr *d = &descr_map[fd];
	size_t len = strlen(d->resp_headers);
	snprintf(d->resp_headers + len, BUFSIZ - len, "%s: %s\r\n", key, value);
}

int axil_header_get(socket_t fd, const char *key, char *buf, size_t buf_len)
{
	char env_key[ENV_KEY_LEN];
	size_t i;

	memcpy(env_key, "HTTP_", 5);
	size_t prefix_len = 5;

	for (i = 0; key[i] && prefix_len + i < sizeof(env_key) - 1; i++) {
		char c = key[i];
		env_key[prefix_len + i] =
		        (c == '-') ? '_' : (char)toupper((unsigned char)c);
	}
	env_key[prefix_len + i] = '\0';

	struct descr *d = &descr_map[fd];
	const char *val = (const char *)corm_get(d->env_hd, env_key);
	if (!val)
		return -1;

	size_t len = strlen(val);
	if (len >= buf_len)
		len = buf_len - 1;
	memcpy(buf, val, len);
	buf[len] = '\0';
	return 0;
}

int axil_env_put(socket_t fd, char *key, char *value)
{
	if (!value)
		return 1;
	struct descr *d = &descr_map[fd];
	corm_put(d->env_hd, key, value);
	return 0;
}

int axil_env_get(socket_t fd, char *target, size_t dest_len, char *key)
{
	struct descr *d = &descr_map[fd];
	const void *skey = corm_get(d->env_hd, key);

	if (!skey)
		return 1;

	stl_strlcpy(target, (const char *)skey, dest_len);
	return 0;
}

int axil_query_parse(char *body)
{
	if (!query_db)
		return -1;

	corm_drop(query_db);

	if (!body || !*body)
		return 0;

	char *copy = strdup(body);
	if (!copy)
		return -1;

	char *saveptr;
	char *pair = strtok_r(copy, "&", &saveptr);

	while (pair) {
		char *eq = strchr(pair, '=');
		if (eq) {
			*eq = '\0';
			char *key = pair;
			char *value = eq + 1;
			size_t vlen = strlen(value);
			char *decoded = malloc(vlen + 1);
			if (decoded) {
				size_t j = 0;
				for (size_t i = 0; value[i] && j < vlen; i++) {
					if (value[i] == '+') {
						decoded[j++] = ' ';
					} else if (
					        value[i] == '%' &&
					        value[i + 1] && value[i + 2])
					{
						unsigned int c;
						sscanf(value + i + 1, "%2x",
						       &c);
						decoded[j++] = (char)c;
						i += 2;
					} else {
						decoded[j++] = value[i];
					}
				}
				decoded[j] = '\0';
				corm_put(query_db, key, decoded);
				free(decoded);
			}
		}
		pair = strtok_r(NULL, "&", &saveptr);
	}

	free(copy);
	return 0;
}

int axil_query_param(const char *name, char *buf, size_t buf_len)
{
	if (!query_db || !buf || !buf_len)
		return -1;

	buf[0] = '\0';

	const char *val = (const char *)corm_get(query_db, name);
	if (!val)
		return -1;

	size_t len = strlen(val);
	if (len >= buf_len)
		len = buf_len - 1;

	memcpy(buf, val, len);
	buf[len] = '\0';
	return (int)len;
}

int axil_req_param(socket_t fd, const char *body, const char *name, char *buf, size_t buf_len)
{
	if (!name || !buf || !buf_len)
		return -1;

	/* 1. Check already parsed query/form database */
	int rc = axil_query_param(name, buf, buf_len);
	if (rc > 0 && buf[0] != '\0')
		return rc;

	/* 2. On-demand parse body if provided, non-empty, and not multipart */
	if (body && body[0] != '\0') {
		char ct[128] = { 0 };
		int is_multipart = 0;
		if (fd > 0) {
			axil_env_get(fd, ct, sizeof(ct), "CONTENT_TYPE");
			if (strstr(ct, "multipart/form-data") != NULL)
				is_multipart = 1;
		}
		if (!is_multipart && body[0] != '-') {
			axil_query_parse((char *)body);
			rc = axil_query_param(name, buf, buf_len);
			if (rc > 0 && buf[0] != '\0')
				return rc;
		}
	}

	/* 3. On-demand parse QUERY_STRING if present */
	if (fd > 0) {
		char qs[1024] = { 0 };
		if (axil_env_get(fd, qs, sizeof(qs), "QUERY_STRING") == 0 && qs[0] != '\0') {
			axil_query_parse(qs);
			rc = axil_query_param(name, buf, buf_len);
			if (rc > 0 && buf[0] != '\0')
				return rc;
		}
	}

	/* 4. Check route pattern env vars */
	if (fd > 0) {
		char env_key[128];
		size_t prefix_len = sizeof("PATTERN_PARAM_") - 1;
		memcpy(env_key, "PATTERN_PARAM_", prefix_len);
		size_t i = 0;
		for (; name[i] && prefix_len + i + 1 < sizeof(env_key); i++) {
			char c = name[i];
			if (c >= 'a' && c <= 'z')
				c -= 32;
			env_key[prefix_len + i] = c;
		}
		env_key[prefix_len + i] = '\0';
		if (axil_env_get(fd, buf, buf_len, env_key) == 0 && buf[0] != '\0')
			return (int)strlen(buf);

		/* Fall back to verbatim case pattern param if uppercase didn't match */
		snprintf(env_key, sizeof(env_key), "PATTERN_PARAM_%s", name);
		if (axil_env_get(fd, buf, buf_len, env_key) == 0 && buf[0] != '\0')
			return (int)strlen(buf);
	}

	return -1;
}

int axil_req_param_int(socket_t fd, const char *body, const char *name, int default_val)
{
	char tmp[32];
	if (axil_req_param(fd, body, name, tmp, sizeof(tmp)) <= 0)
		return default_val;
	char *end = NULL;
	long val = strtol(tmp, &end, 10);
	if (end == tmp)
		return default_val;
	return (int)val;
}

int axil_req_param_bool(socket_t fd, const char *body, const char *name, int default_val)
{
	char tmp[16];
	if (axil_req_param(fd, body, name, tmp, sizeof(tmp)) <= 0)
		return default_val;
	if (strcmp(tmp, "1") == 0 || strcasecmp(tmp, "true") == 0 ||
	    strcasecmp(tmp, "on") == 0 || strcasecmp(tmp, "yes") == 0)
		return 1;
	if (strcmp(tmp, "0") == 0 || strcasecmp(tmp, "false") == 0 ||
	    strcasecmp(tmp, "off") == 0 || strcasecmp(tmp, "no") == 0)
		return 0;
	return default_val;
}

int axil_param(socket_t fd, const char *name, char *buf, size_t buf_len)
{
	return axil_req_param(fd, NULL, name, buf, buf_len);
}

int axil_param_int(socket_t fd, const char *name, int default_val)
{
	return axil_req_param_int(fd, NULL, name, default_val);
}

int axil_param_bool(socket_t fd, const char *name, int default_val)
{
	return axil_req_param_bool(fd, NULL, name, default_val);
}
