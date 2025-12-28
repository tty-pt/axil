#ifndef IIO_H
#define IIO_H

#include <stdio.h>

#ifdef _WIN32
typedef unsigned io_size_t;
typedef long io_ssize_t;
#else
typedef size_t io_size_t;
typedef ssize_t io_ssize_t;
#endif

typedef io_ssize_t (*io_t)(socket_t fd, void *data, io_size_t len, int flags);

struct io {
	io_t read, write, lower_read, lower_write;
};

extern struct io io[FD_SETSIZE];

#endif
