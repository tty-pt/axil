#include <node_api.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define AXIL_NO_MAIN
#include "../../src/axil.c"

static char *extract_utf8(napi_env env, napi_value val, size_t *out_len) {
	size_t len = 0;
	if (napi_get_value_string_utf8(env, val, NULL, 0, &len) != napi_ok)
		return NULL;
	char *buf = (char *)malloc(len + 1);
	if (!buf)
		return NULL;
	napi_get_value_string_utf8(env, val, buf, len + 1, &len);
	buf[len] = '\0';
	if (out_len)
		*out_len = len;
	return buf;
}

/* cli(args: string[]) -> number */
static napi_value AxilCli(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);

	uint32_t arr_len = 0;
	if (argc >= 1) {
		bool is_arr = false;
		napi_is_array(env, args[0], &is_arr);
		if (is_arr)
			napi_get_array_length(env, args[0], &arr_len);
	}

	/* Allocate argv: ["axil", "-d", ...user_args, NULL] */
	int c_argc = 0;
	char **c_argv = (char **)calloc((size_t)arr_len + 3, sizeof(char *));
	if (!c_argv) {
		napi_throw_error(env, NULL, "Out of memory allocating argv");
		return NULL;
	}

	bool has_help = false;
	for (uint32_t i = 0; i < arr_len; i++) {
		napi_value el;
		napi_get_element(env, args[0], i, &el);
		char *s = extract_utf8(env, el, NULL);
		if (!s) continue;
		if (i == 0 && strcmp(s, "axil") == 0) {
			free(s);
			continue;
		}
		if (strcmp(s, "-?") == 0)
			has_help = true;
		if (c_argc == 0) {
			c_argv[c_argc++] = strdup("axil");
			c_argv[c_argc++] = strdup("-d");
		}
		c_argv[c_argc++] = s;
	}

	if (c_argc == 0) {
		c_argv[c_argc++] = strdup("axil");
		if (!has_help)
			c_argv[c_argc++] = strdup("-d");
	}
	c_argv[c_argc] = NULL;

	int rc = axil_cli(c_argc, c_argv);

	for (int i = 0; i < c_argc; i++)
		free(c_argv[i]);
	free(c_argv);

	napi_value res;
	napi_create_int32(env, rc, &res);
	return res;
}

/* statusText(code: number) -> string */
static napi_value AxilStatusText(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);

	int32_t code = 200;
	if (argc >= 1)
		napi_get_value_int32(env, args[0], &code);

	const char *txt = axil_status_text((int)code);
	napi_value res;
	napi_create_string_utf8(env, txt ? txt : "Unknown", NAPI_AUTO_LENGTH, &res);
	return res;
}

/* urlEncode(input: string) -> string */
static napi_value AxilUrlEncode(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t in_len = 0;
	char *in = extract_utf8(env, args[0], &in_len);
	if (!in) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t out_cap = in_len * 3 + 16;
	char *out = (char *)malloc(out_cap);
	if (!out) {
		free(in);
		napi_throw_error(env, NULL, "Out of memory");
		return NULL;
	}
	int written = axil_url_encode(in, out, out_cap);
	free(in);
	if (written < 0) {
		free(out);
		napi_throw_error(env, NULL, "URL encode buffer overflow");
		return NULL;
	}
	napi_value res;
	napi_create_string_utf8(env, out, (size_t)written, &res);
	free(out);
	return res;
}

/* urlDecode(input: string) -> string */
static napi_value AxilUrlDecode(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t in_len = 0;
	char *in = extract_utf8(env, args[0], &in_len);
	if (!in) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t out_cap = in_len + 16;
	char *out = (char *)malloc(out_cap);
	if (!out) {
		free(in);
		napi_throw_error(env, NULL, "Out of memory");
		return NULL;
	}
	size_t written = axil_url_decode(in, in_len, out, out_cap);
	free(in);
	napi_value res;
	napi_create_string_utf8(env, out, written, &res);
	free(out);
	return res;
}

/* jsonEscape(input: string) -> string */
static napi_value AxilJsonEscape(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t in_len = 0;
	char *in = extract_utf8(env, args[0], &in_len);
	if (!in) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t out_cap = in_len * 6 + 16;
	char *out = (char *)malloc(out_cap);
	if (!out) {
		free(in);
		napi_throw_error(env, NULL, "Out of memory");
		return NULL;
	}
	axil_json_escape(in, out, out_cap);
	free(in);
	napi_value res;
	napi_create_string_utf8(env, out, NAPI_AUTO_LENGTH, &res);
	free(out);
	return res;
}

/* slugify(input: string) -> string */
static napi_value AxilSlugify(napi_env env, napi_callback_info info) {
	size_t argc = 1;
	napi_value args[1];
	napi_get_cb_info(env, info, &argc, args, NULL, NULL);
	if (argc < 1) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t in_len = 0;
	char *in = extract_utf8(env, args[0], &in_len);
	if (!in) {
		napi_throw_type_error(env, NULL, "Expected string argument");
		return NULL;
	}
	size_t out_cap = in_len * 2 + 32;
	char *out = (char *)malloc(out_cap);
	if (!out) {
		free(in);
		napi_throw_error(env, NULL, "Out of memory");
		return NULL;
	}
	axil_slugify(in, in_len, out, out_cap);
	free(in);
	napi_value res;
	napi_create_string_utf8(env, out, NAPI_AUTO_LENGTH, &res);
	free(out);
	return res;
}

static napi_value Init(napi_env env, napi_value exports) {
	napi_property_descriptor props[] = {
		{ "cli", NULL, AxilCli, NULL, NULL, NULL, napi_default, NULL },
		{ "statusText", NULL, AxilStatusText, NULL, NULL, NULL, napi_default, NULL },
		{ "urlEncode", NULL, AxilUrlEncode, NULL, NULL, NULL, napi_default, NULL },
		{ "urlDecode", NULL, AxilUrlDecode, NULL, NULL, NULL, napi_default, NULL },
		{ "jsonEscape", NULL, AxilJsonEscape, NULL, NULL, NULL, napi_default, NULL },
		{ "slugify", NULL, AxilSlugify, NULL, NULL, NULL, napi_default, NULL },
	};
	napi_define_properties(env, exports, sizeof(props) / sizeof(props[0]), props);
	return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)
