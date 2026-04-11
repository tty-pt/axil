#ifndef NDC_INTERNAL_H
#define NDC_INTERNAL_H

#include "ndc-platform.h"
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

extern struct descr descr_map[FD_SETSIZE];
extern socket_t tunnel_pair[FD_SETSIZE];
extern fd_set fds_read, fds_active, fds_write, fds_wactive;
extern struct timeval exec_timeout;
extern int do_cleanup;
extern int ndc_srv_flags;
void _ndc_cert_add(char *domain, char *crt, char *key);
void do_GET_cb(int fd, char *buf, size_t len, int ofd);

#endif
