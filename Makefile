all := libndc ndc

LDLIBS-libndc-Linux := -lrt
LDLIBS-libndc := -lqmap -lqsys -lcrypto -lssl
LDLIBS-libndc-Linux := -lc
LDLIBS-libndc-Windows := -lws2_32
LDLIBS-ndc := -lndc -lndx -lqsys

CFLAGS := -g
LDFLAGS-libndc-Darwin := -Wl,-undefined,dynamic_lookup
CFLAGS-Windows := -masm=intel

-include ../mk/include.mk
