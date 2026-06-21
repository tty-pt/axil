all := libaxil axil test test-auth test-routes
INSTALL_BIN := axil

LDLIBS-libaxil-Linux := -lrt
LDLIBS-libaxil-OpenBSD := -liconv
LDLIBS-libaxil := -lqmap -lqsys -lcrypto -lssl -lxylem
LDFLAGS-libaxil-Darwin := -undefined dynamic_lookup
LDLIBS-libaxil-Linux := -lc
LDLIBS-libaxil-Windows := -lws2_32
LDLIBS-axil := -laxil -lxylem -lqsys
LDLIBS-test := -laxil
LDLIBS-test-auth := -laxil -lqsys
LDLIBS-test-routes := -laxil

CFLAGS := -g
CFLAGS-Windows := -masm=intel

libaxil-obj-y-Linux := src/axil-posix.o
libaxil-obj-y-Darwin := src/axil-posix.o
libaxil-obj-y-OpenBSD := src/axil-posix.o
libaxil-obj-y-Msys := src/axil-win.o
libaxil-obj-y-MingW := src/axil-win.o
libaxil-obj-y-MinGW64 := src/axil-win.o
libaxil-obj-y := src/axil-status.o src/axil-encode.o

-include ../mk/include.mk

docs: docs-cli

docs-cli:
	doxygen Doxyfile-cli

test: all
	sh ./test.sh

objects-set.mk: Makefile
