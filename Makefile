all := libndc ndc test test-auth test-routes
INSTALL_BIN := ndc

LDLIBS-libndc-Linux := -lrt
LDLIBS-libndc := -lqmap -lqsys -lcrypto -lssl -lndx
LDFLAGS-libndc-Darwin := -undefined dynamic_lookup
LDLIBS-libndc-Linux := -lc
LDLIBS-libndc-Windows := -lws2_32
LDLIBS-ndc := -lndc -lndx -lqsys
LDLIBS-test := -lndc
LDLIBS-test-auth := -lndc -lqsys
LDLIBS-test-routes := -lndc

CFLAGS := -g
CFLAGS-Windows := -masm=intel

libndc-obj-y-Linux := src/ndc-posix.o
libndc-obj-y-Darwin := src/ndc-posix.o
libndc-obj-y-OpenBSD := src/ndc-posix.o
libndc-obj-y-Msys := src/ndc-win.o
libndc-obj-y-MingW := src/ndc-win.o
libndc-obj-y-MinGW64 := src/ndc-win.o
libndc-obj-y := src/ndc-status.o

-include ../mk/include.mk

docs: docs-cli

docs-cli:
	doxygen Doxyfile-cli

test: all
	sh ./test.sh

objects-set.mk: Makefile
