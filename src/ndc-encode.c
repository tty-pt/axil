#include <ctype.h>
#include <errno.h>
#include <iconv.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "../include/ttypt/ndc.h"

static int hex_digit_value(int ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0';
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 10;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 10;
	return -1;
}

int ndc_url_encode(const char *in, char *out, size_t outlen)
{
	size_t j = 0;

	for (size_t i = 0; in[i] && j + 4 < outlen; i++) {
		unsigned char c = (unsigned char)in[i];

		if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')
		{
			out[j++] = c;
		} else {
			j += snprintf(out + j, outlen - j, "%%%02X", c);
		}
	}

	out[j] = '\0';
	return (int)j;
}

size_t ndc_url_decode(const char *src, size_t src_len,
                      char *out, size_t out_len)
{
	size_t si;
	size_t oi;

	if (!out || out_len == 0)
		return 0;

	oi = 0;
	for (si = 0; si < src_len && oi + 1 < out_len; si++) {
		if (src[si] == '+') {
			out[oi++] = ' ';
			continue;
		}
		if (src[si] == '%' && si + 2 < src_len) {
			int hi;
			int lo;

			hi = hex_digit_value(src[si + 1]);
			lo = hex_digit_value(src[si + 2]);
			if (hi >= 0 && lo >= 0) {
				out[oi++] = (char)((hi << 4) | lo);
				si += 2;
				continue;
			}
		}
		out[oi++] = src[si];
	}
	out[oi] = '\0';
	return oi;
}

int ndc_json_escape(const char *in, char *out, size_t outlen)
{
	size_t j = 0;

	for (size_t i = 0; in[i] && j + 2 < outlen; i++) {
		unsigned char c = (unsigned char)in[i];

		if (c == '"' || c == '\\') {
			out[j++] = '\\';
			out[j++] = c;
		} else if (c == '\n') {
			out[j++] = '\\';
			out[j++] = 'n';
		} else if (c == '\r') {
			out[j++] = '\\';
			out[j++] = 'r';
		} else if (c == '\t') {
			out[j++] = '\\';
			out[j++] = 't';
		} else if (c < 0x20) {
			if (j + 6 >= outlen)
				break;
			j += snprintf(out + j, outlen - j, "\\u%04x", c);
		} else {
			out[j++] = c;
		}
	}

	out[j] = '\0';
	return 0;
}

int ndc_slugify(const char *title, size_t title_len,
                char *result, size_t result_len)
{
	static iconv_t cd = (iconv_t)-1;
	size_t written;
	char *r_ptr = result;
	char *w_ptr = result;
	char *in;
	char *out;
	size_t in_len;
	size_t out_len;
	size_t i;

	if (!title || !result || result_len == 0)
		return -1;

	if (cd == (iconv_t)-1)
		cd = iconv_open("ASCII//TRANSLIT", "UTF-8");

	if (cd != (iconv_t)-1) {
		in = (char *)title;
		in_len = title_len;
		out = result;
		out_len = result_len - 1;

		while (in_len > 0 && out_len > 0) {
			size_t res =
			        iconv(cd, (void *)&in, &in_len, &out, &out_len);
			if (res != (size_t)-1)
				continue;
			if (errno != EILSEQ && errno != EINVAL)
				break;
			in++;
			in_len--;
			iconv(cd, NULL, NULL, &out, &out_len);
		}
		written = (size_t)(out - result);
	} else {
		size_t to_copy =
		        title_len < result_len ? title_len : result_len - 1;
		memcpy(result, title, to_copy);
		written = to_copy;
	}

	for (i = 0; i < written; i++) {
		char c = r_ptr[i];
		if (c == ' ')
			*w_ptr++ = '_';
		else if (c >= 'A' && c <= 'Z')
			*w_ptr++ = c + 32;
		else if ((c >= 'a' && c <= 'z') ||
		         (c >= '0' && c <= '9') || c == '_')
			*w_ptr++ = c;
	}
	*w_ptr = '\0';

	if (w_ptr == result)
		snprintf(result, result_len, "item");

	return 0;
}
