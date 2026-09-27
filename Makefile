all := libaxil axil test test-auth test-routes test-defer
INSTALL_BIN := axil

LDLIBS-libaxil-Linux := -lrt
LDLIBS-libaxil-OpenBSD := -liconv
LDLIBS-libaxil := -lcorm -lqsys -lcrypto -lssl -lxylem
LDFLAGS-libaxil-Darwin := -undefined dynamic_lookup
LDLIBS-libaxil-Linux := -lc
LDLIBS-libaxil-Windows := -lws2_32 -liconv
LDLIBS-axil := -laxil -lxylem -lqsys
LDLIBS-test := -laxil
LDLIBS-test-auth := -laxil -lqsys
LDLIBS-test-routes := -laxil -lcrypto
# The only OpenSSL use in test-routes is the WebSocket upstream child, which is
# #ifndef _WIN32, and mingw has no -lcrypto.
LDLIBS-test-routes-Windows :=
LDLIBS-test-defer := -laxil

CFLAGS := -g
CFLAGS-Windows := -masm=intel

SANITIZE ?= 0
CFLAGS-SANITIZE-1 = -fsanitize=address -fsanitize=undefined -fno-omit-frame-pointer
LDFLAGS-SANITIZE-1 = -fsanitize=address -fsanitize=undefined
CFLAGS += ${CFLAGS-SANITIZE-${SANITIZE}}
LDFLAGS += ${LDFLAGS-SANITIZE-${SANITIZE}}

libaxil-obj-y-Linux := src/axil-posix.o
libaxil-obj-y-Darwin := src/axil-posix.o
libaxil-obj-y-OpenBSD := src/axil-posix.o
libaxil-obj-y-Msys := src/axil-win.o
libaxil-obj-y-MingW := src/axil-win.o
libaxil-obj-y-MinGW64 := src/axil-win.o
libaxil-obj-y := src/axil-status.o src/axil-encode.o

-include ../mk/include.mk

test: all
	sh ./test.sh

objects-set.mk: Makefile
