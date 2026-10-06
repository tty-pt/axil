#include "../include/ws.h"
#include "../include/iio.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <errno.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <ttypt/qsys.h>

/* The 7-bit payload length field doubles as a form selector: below 126 it is
 * the length itself, and 126/127 select the 2-/8-byte extended forms. */
#define OPCODE(head) ((unsigned char) (head[0] & 0x0f))
#define PAYLOAD_LEN(head) ((unsigned char) (head[1] & 0x7f))
#define MASK_BIT(head) ((unsigned char) ((head)[1] & 0x80))
#define WS_LEN_16BIT 126
#define WS_LEN_64BIT 127
#define WS_OP_CLOSE  8
/* Control frames -- close, ping, pong -- are the opcodes whose 0x08 bit is set
 * in the 4-bit opcode field (RFC 6455 5.5). One is never fragmented and cannot
 * be interleaved with a fragmented message, so its payload is capped at 125
 * bytes (RFC 6455 5.5). */
#define IS_CONTROL(op) (((op) & 0x08) != 0)
#define WS_CTRL_MAX_PL 125
/* Close codes, RFC 6455 7.4.1. */
#define WS_CLOSE_NORMAL           1000
#define WS_CLOSE_PROTOCOL_ERROR   1002
#define WS_CLOSE_POLICY_VIOLATION 1008
/* FIN set on opcode 8: a complete, unfragmented close frame. */
#define WS_FIN_CLOSE 0x88

/* Defined below, in libaxil.c, which includes this file first. */
static io_ssize_t axil_low_write(socket_t fd, void *from, io_size_t len, int flags);

enum ws_flags {
	WS_BINARY = 0x2,
	WS_FIN = 0x80,
};

int ws_flags[FD_SETSIZE];

#ifdef __OpenBSD__
int __b64_ntop(unsigned char const *src, size_t srclength,
	       char *target, size_t targsize);
#define b64_ntop(...) __b64_ntop(__VA_ARGS__)
#else

#include <stdint.h>

// https://github.com/yasuoka/base64/blob/master/b64_ntop.c

int
b64_ntop(u_char *src, size_t srclength, char *target, size_t target_size)
{
  size_t expect_siz, i;
  int		 j;
  uint32_t	 bit24;
  const char	 b64str[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  expect_siz = ((srclength + 2) / 3) * 4 + 1;

  if (target == NULL)
    return (expect_siz);
  if (target_size < expect_siz)
    return (-1);

  for (i = 0, j = 0; i < srclength; i += 3) {
    bit24 = src[i] << 16;
    if (i + 1 < srclength)
      bit24 |= src[i + 1] << 8;
    if (i + 2 < srclength)
      bit24 |= src[i + 2];

    target[j++] = b64str[(bit24 & 0xfc0000) >> 18];
    target[j++] = b64str[(bit24 & 0x03f000) >> 12];
    if (i + 1 < srclength)
      target[j++] = b64str[(bit24 & 0x000fc0) >> 6];
    else
      target[j++] = '=';
    if (i + 2 < srclength)
      target[j++] = b64str[(bit24 & 0x00003f)];
    else
      target[j++] = '=';
  }
  target[j] = '\0';

  return j;
}

#endif

struct ws_frame {
	/* Partial-frame state, so a frame split across TCP segments (or across
	 * select() passes) resumes where it left off instead of being discarded.
	 * hread/lread/mread/xread count the bytes already consumed. */
	uint8_t head[2];
	size_t hread;        /* basic header */
	size_t lread;        /* extended payload length */
	size_t mread;        /* masking key */
	size_t xread;        /* payload */
	uint8_t pl_set;      /* pl is valid */
	uint64_t pl;        /* payload length */
	uint8_t len[8];     /* raw extended length */
	char mk[4];
	/* Payload is heap-allocated: a 64-bit-form frame may declare far more
	 * than BUFSIZ, and the fixed buffer overflowed into the neighbouring frame. */
	uint8_t *data;
} frame_map[FD_SETSIZE];

/* Byte order helpers. htonl()/ntohl() are identity on a big-endian host, so
 * these need no conditional compilation.
 * Not named htonll()/ntohll(): Darwin defines those as macros in
 * <sys/_endian.h>, so a static function of that name expands into its own
 * declaration and fails to compile. */
static uint64_t
ws_htonll(uint64_t v)
{
	uint32_t lo = (uint32_t)v, hi = (uint32_t)(v >> 32);
	return ((uint64_t)htonl(lo) << 32) | htonl(hi);
}

static uint64_t
ws_ntohll(uint64_t v)
{
	uint32_t lo = (uint32_t)v, hi = (uint32_t)(v >> 32);
	return ((uint64_t)ntohl(lo) << 32) | ntohl(hi);
}

	/* Largest payload accepted from a peer. 64-bit lengths are peer-controlled,
	 * so an unbounded malloc() is a denial-of-service vector. */
#define WS_MAX_PAYLOAD (64ULL * 1024 * 1024)

static void
ws_frame_reset(socket_t cfd)
{
	free(frame_map[cfd].data);
	memset(&frame_map[cfd], 0, sizeof(struct ws_frame));
}

int
ws_init(socket_t cfd, char *ws_key) {
#ifdef _WIN32
	fprintf(stderr, "ws_init %lld %s\n", cfd, ws_key);
#else
	fprintf(stderr, "ws_init %d %s\n", cfd, ws_key);
#endif
	static char common_resp[]
		= "HTTP/1.1 101 Switching Protocols\r\n"
		"Upgrade: websocket\r\n"
		"Connection: upgrade\r\n"
		"Sec-Websocket-Protocol: binary\r\n"
		"Sec-Websocket-Accept: 00000000000000000000000000000\r\n\r\n";
	unsigned char hash[EVP_MAX_MD_SIZE];
	EVP_MD_CTX *mdctx;
	unsigned int hash_len;

	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_sha1(), NULL);
	EVP_DigestUpdate(mdctx, ws_key, strlen(ws_key));
	EVP_DigestUpdate(mdctx, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11", 36);

	EVP_DigestFinal_ex(mdctx, hash, &hash_len);
	EVP_MD_CTX_free(mdctx);

	b64_ntop(hash, SHA_DIGEST_LENGTH, common_resp + 129, 29);
	memcpy(common_resp + 129 + 28, "\r\n\r\n", 5);
	io[cfd].lower_write(cfd, common_resp, 129 + 28 + 4, 0);
	ws_frame_reset(cfd);
	ws_flags[cfd] = WS_BINARY | WS_FIN;
	return 0;
}

io_ssize_t
ws_write(socket_t cfd, void *data, io_size_t n, int flags UNUSED)
{
	unsigned char hbuf[2 + 8];
	size_t hlen = 0;

	if (!FD_VALID(cfd)) {
		errno = EBADF;
		return -1;
	}

	hbuf[hlen++] = ws_flags[cfd] & (WS_BINARY | WS_FIN);

	if (n < WS_LEN_16BIT) {
		hbuf[hlen++] = n;
	} else if (n < (1 << 16)) {
		uint16_t nn = htons(n);
		hbuf[hlen++] = WS_LEN_16BIT;
		memcpy(hbuf + hlen, &nn, sizeof(nn));
		hlen += sizeof(nn);
	} else {
		/* htonl() would byte-swap only the low word and leave the high word as
		 * zero on a little-endian host. */
		uint64_t nn = ws_htonll(n);
		hbuf[hlen++] = WS_LEN_64BIT;
		memcpy(hbuf + hlen, &nn, sizeof(nn));
		hlen += sizeof(nn);
	}

	/* Header and payload take the same queue, so the pieces either enter
	 * d->remaining in order or go out back to back: frames cannot interleave
	 * and neither half is lost to EAGAIN.
	 *
	 * -1 from axil_low_write() means "queued", not "lost". A real write error
	 * closes the fd instead, and axil_close() memsets the descr and sets
	 * d->fd = -1, so a descriptor that no longer maps to itself is how the two
	 * are told apart. */
	if (axil_low_write(cfd, hbuf, hlen, 0) < 0 && descr_map[cfd].fd != cfd)
		return -1;
	if (n && axil_low_write(cfd, data, n, 0) < 0 && descr_map[cfd].fd != cfd)
		return -1;

	/* Wholly written or wholly queued, so the frame size is the honest
	 * return: a queue that took the payload is not a failed write. */
	return (io_ssize_t)(hlen + n);
}

/* One frame, one write: the status is 2 big-endian bytes after a fixed 2-byte
 * header, and the two must not be split by an EAGAIN in between. RFC 6455
 * 7.4.1. */
static void
ws_close_status(socket_t cfd, unsigned status)
{
	unsigned char frame[4];

	/* Also the guard for ws_close(), which has no other array access. */
	if (!FD_VALID(cfd))
		return;

	frame[0] = WS_FIN_CLOSE;
	frame[1] = 0x02;
	frame[2] = (unsigned char) (status >> 8);
	frame[3] = (unsigned char) (status & 0xff);

	if (io[cfd].lower_write(cfd, frame, sizeof(frame), 0) != (ssize_t)sizeof(frame))
		WARN("ws_close %d: close frame not delivered\n", cfd);

	/* Drop any partially received frame: axil_close() frees d->remaining before
	 * calling us, so without this the payload stayed allocated for the lifetime
	 * of the process and was still pointed at by frame_map[cfd] when the fd
	 * number came round again. */
	ws_frame_reset(cfd);
}

void
ws_close(socket_t cfd)
{
	/* Teardown policy, not a protocol violation: a violation found while
	 * *reading* gets WS_CLOSE_PROTOCOL_ERROR, where the connection is still
	 * live. Here axil_close() has already freed the write queue, so there is
	 * nowhere to queue a frame the socket will not take right now. A short
	 * write is not recoverable, but it is no longer silently discarded. */
	ws_close_status(cfd, WS_CLOSE_POLICY_VIOLATION);
}

/* Test hook: report EINTR once while reading a frame *payload*, so the retry in
 * ws_fill() can be exercised without racing a real signal. Define
 * AXIL_NO_TEST_HOOKS to strip it. On by default because test.sh and proof.sh
 * drive it through AXIL_TEST_WS_EINTR. */
#ifndef AXIL_NO_TEST_HOOKS
#define WS_EINTR_TEST_HOOK 1
static int ws_eintr_test = -1;
#endif

/* Consume exactly `need` bytes into buf. Returns 0 when the run completed and
 * -1 when the socket would block part-way (*got is left untouched, so the next
 * call resumes) or the peer closed. *eof distinguishes the two. */
static int
ws_fill(socket_t cfd, uint8_t *buf, size_t *got, size_t need, int *eof)
{
	*eof = 0;
	while (*got < need) {
		ssize_t n;

#ifdef WS_EINTR_TEST_HOOK
		if (ws_eintr_test < 0)
			ws_eintr_test = getenv("AXIL_TEST_WS_EINTR") ? 1 : 0;
		if (ws_eintr_test && buf == frame_map[cfd].data) {
			ws_eintr_test = 0;
			errno = EINTR;
			n = -1;
		} else
#endif
			n = io[cfd].lower_read(cfd, buf + *got, need - *got, 0);
		if (n == 0) {
			*eof = 1;
			return -1;
		}
		if (n < 0) {
			/* A signal handler that ran during the read makes it fail with
			 * EINTR. That is neither a closed peer nor a protocol error, and
			 * the unread bytes are still in the socket, so retry rather than
			 * report EOF: discarding the frame here would let the *next* call
			 * parse the leftover payload as a fresh frame header. */
			if (errno == EINTR)
				continue;
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				*eof = 1;
			return -1;
		}
		*got += (size_t)n;
	}
	return 0;
}

io_ssize_t
ws_read(socket_t cfd, void *data, io_size_t len, int flags UNUSED)
{
	uint64_t pl, i;
	int eof;

	/* Before the frame_map[] index, not after. */
	if (!FD_VALID(cfd)) {
		errno = EBADF;
		return -1;
	}

	struct ws_frame *frame = &frame_map[cfd];

	/* A zero-length destination is a caller error, refused before any parsing
	 * so it costs no frame state and no allocation. The bounds check at the
	 * end cannot catch it: `len` is itself part of the condition guarding that
	 * copy, so len == 0 would skip the check and then write pl + 1 bytes. */
	if (data && len == 0) {
		errno = EMSGSIZE;
		return -1;
	}

	/* Basic header. */
	if (frame->hread < sizeof(frame->head)) {
		if (ws_fill(cfd, frame->head, &frame->hread, sizeof(frame->head),
		            &eof)) {
			if (eof) {
				ws_frame_reset(cfd);
				return 0;
			}
			return -1;      /* resume when the socket is readable again */
		}
	}

	/* Client-to-server frames must be masked (RFC 6455 5.1), tested here
	 * immediately after the 2-byte header so a clear bit fails before the
	 * extended length is read. A clear bit also means the byte stream is
	 * already out of step -- there is no length that would put it back -- so
	 * the connection is failed rather than salvaged. */
	if (!MASK_BIT(frame->head)) {
		WARN("ws_read %d: client frame is not masked\n", cfd);
		ws_close_status(cfd, WS_CLOSE_PROTOCOL_ERROR);
		errno = EPROTO;
		return -1;
	}

	/* Decided from the 2 header bytes alone, before the extended length is
	 * read, so an oversized control frame never reaches the parser below or
	 * allocates anything. Both extended forms are >125 by construction, so
	 * testing for either is the whole test.
	 *
	 * This must stay *above* the opcode 8 branch, and after the mask test:
	 * returning before the extended length is parsed would leave a close frame
	 * declaring 126/127 looking like a valid close, and the next frame would
	 * read its unread length bytes as a header. Ordering it here also refuses an
	 * unmasked *close* like any other unmasked client frame. */
	if (IS_CONTROL(OPCODE(frame->head)) &&
	    PAYLOAD_LEN(frame->head) >= WS_LEN_16BIT) {
		WARN("ws_read %d: control frame declares more than %d bytes\n",
		     cfd, WS_CTRL_MAX_PL);
		ws_close_status(cfd, WS_CLOSE_PROTOCOL_ERROR);
		errno = EPROTO;
		return -1;
	}

	if (OPCODE(frame->head) == WS_OP_CLOSE) {
		/* RFC 6455 5.5.1: a peer that receives a Close frame and has not
		 * already sent one MUST send a Close frame in response before closing
		 * the connection. Returning 0 tells the caller to close; what this
		 * branch owes the peer is the frame.
		 *
		 * WS_CLOSE_NORMAL rather than the peer's own status: echoing the status
		 * back is a SHOULD, not a MUST, and the payload carrying it has not been
		 * read yet -- this runs on the 2-byte header alone. Reading it first
		 * would need a remembered "this frame is a close" bit so a half-arrived
		 * close could resume, which is more state than a SHOULD is worth. The
		 * payload is left unread, which is harmless: nothing will parse it.
		 *
		 * The echo has to happen from in here because unlike the axil_close()
		 * path the connection is still live, so the write queue has not been
		 * freed yet. ws_close_status() also does the frame reset for us. */
		ws_close_status(cfd, WS_CLOSE_NORMAL);
		return 0;
	}

	/* Extended length, in network byte order. */
	if (!frame->pl_set) {
		pl = PAYLOAD_LEN(frame->head);

		if (pl == WS_LEN_16BIT) {
			uint16_t rpl;
			if (ws_fill(cfd, frame->len, &frame->lread, 2, &eof)) {
				if (eof) {
					ws_frame_reset(cfd);
					return 0;
				}
				return -1;
			}
			memcpy(&rpl, frame->len, sizeof(rpl));
			pl = ntohs(rpl);
		} else if (pl == WS_LEN_64BIT) {
			uint64_t rpl;
			if (ws_fill(cfd, frame->len, &frame->lread, 8, &eof)) {
				if (eof) {
					ws_frame_reset(cfd);
					return 0;
				}
				return -1;
			}
			memcpy(&rpl, frame->len, sizeof(rpl));
			pl = ws_ntohll(rpl);
		}

		/* A 64-bit length is peer-controlled, so cap the allocation. */
		if (pl > WS_MAX_PAYLOAD) {
			WARN("ws_read %d: payload of %llu bytes exceeds the %llu byte limit\n",
			     cfd, (unsigned long long)pl,
			     (unsigned long long)WS_MAX_PAYLOAD);
			ws_frame_reset(cfd);
			errno = EMSGSIZE;
			return -1;
		}

		frame->pl = pl;
		frame->pl_set = 1;
	}

	/* Masking key. */
	if (frame->mread < sizeof(frame->mk)) {
		if (ws_fill(cfd, (uint8_t *)frame->mk, &frame->mread,
		            sizeof(frame->mk), &eof)) {
			if (eof) {
				ws_frame_reset(cfd);
				return 0;
			}
			return -1;
		}
	}

	/* Payload, heap-allocated to whatever the frame declared. One spare byte
	 * holds the NUL terminator. */
	if (!frame->data) {
		frame->data = malloc((size_t)frame->pl + 1);
		if (!frame->data) {
			ws_frame_reset(cfd);
			errno = ENOMEM;
			return -1;
		}
	}
	if (ws_fill(cfd, frame->data, &frame->xread, (size_t)frame->pl, &eof)) {
		if (eof) {
			ws_frame_reset(cfd);
			return 0;
		}
		return -1;          /* partial frame retained for the next call */
	}

	for (i = 0; i < frame->pl; i++)
		frame->data[i] ^= frame->mk[i % 4];

	frame->data[frame->pl] = '\0';

	pl = frame->pl;

	/* The payload plus its terminator is copied out, so a caller-supplied
	 * length that is too small is refused rather than overrunning the
	 * caller's buffer. A length of 0 means "unspecified" only when data is
	 * NULL: a non-NULL data with len 0 was already refused above, before any
	 * frame state was allocated. */
	if (data && len && pl + 1 > (uint64_t)len) {
		ws_frame_reset(cfd);
		errno = EMSGSIZE;
		return -1;
	}
	if (data)
		memcpy(data, frame->data, (size_t)pl + 1);

	ws_frame_reset(cfd);
	return (io_ssize_t)pl;
}

int
ws_dprintf(socket_t fd, const char *format, va_list ap)
{
	static char buf[BUFSIZ];

	/* ws_flags[fd] is written below, before ws_write() could check. */
	if (!FD_VALID(fd)) {
		errno = EBADF;
		return -1;
	}

	/* vsnprintf returns the length it *would* have written, so a formatted
	 * message of BUFSIZ bytes or more came back with a length past the end of
	 * this static buffer, and ws_write() then framed and sent that many bytes.
	 * Clamp it the way axil_dwritef() does: vsnprintf has already truncated
	 * the output to sizeof(buf) - 1 characters and NUL-terminated, so the
	 * clamped length is also the true length of what was formatted. */
	ssize_t len = vsnprintf(buf, sizeof(buf), format, ap);

	if (len < 0 || (size_t)len >= sizeof(buf))
		len = sizeof(buf) - 1;

	/* `|` not `&`: the two are disjoint bits, so `WS_BINARY & WS_FIN` is 0. */
	ws_flags[fd] = WS_BINARY | WS_FIN;
	return ws_write(fd, buf, (io_size_t)len, 0);
}

int
ws_printf(socket_t fd, const char *format, ...)
{
	ssize_t len;
	va_list args;
	va_start(args, format);
	len = ws_dprintf(fd, format, args);
	va_end(args);
	return len;
}
