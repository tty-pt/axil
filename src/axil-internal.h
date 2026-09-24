#ifndef AXIL_INTERNAL_H
#define AXIL_INTERNAL_H

#include "axil-platform.h"
#include "../include/iio.h"

#include <openssl/ssl.h>
#include <sys/time.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#include <pwd.h>
#include <sys/ioctl.h>
#include <termios.h>
int axil_write_remaining(socket_t fd);
#endif

struct descr {
	SSL *cSSL;
	socket_t fd;
	int flags, pty, epid;
	char username[BUFSIZ];
	char *remaining;
	struct sockaddr_in addr;
	size_t remaining_size, remaining_len, remaining_off;
	time_t sor; // start of request
	int pipes[3], pipes_mask;
	cmd_cb_t callback;
	size_t total;
#ifndef _WIN32
	struct winsize wsz;
	struct termios tty;
	struct passwd pw;
	int pid;
#endif
	unsigned env_hd;
	char resp_headers[BUFSIZ];
};

#ifndef AXIL_HIDDEN
#if (defined(__GNUC__) || defined(__clang__)) && !defined(_WIN32)
#define AXIL_HIDDEN __attribute__((visibility("hidden")))
#else
#define AXIL_HIDDEN
#endif
#endif

extern struct descr descr_map[FD_SETSIZE] AXIL_HIDDEN;
extern socket_t tunnel_pair[FD_SETSIZE] AXIL_HIDDEN;
extern fd_set fds_read, fds_active, fds_write, fds_wactive AXIL_HIDDEN;
extern struct timeval exec_timeout AXIL_HIDDEN;
extern int do_cleanup AXIL_HIDDEN;
extern int axil_srv_flags AXIL_HIDDEN;
void _axil_cert_add(char *domain, char *crt, char *key);

int axil_write_remaining(socket_t fd);
#endif
