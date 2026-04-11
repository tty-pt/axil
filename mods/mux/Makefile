NDC_PREFIX  ?= /usr/local
NDC_HTDOCS  ?= $(NDC_PREFIX)/share/ndc/htdocs
NDC_INCDIR  ?= $(NDC_PREFIX)/include
NDC_LIBDIR  ?= $(NDC_PREFIX)/lib
INSTALL_DIR ?= $(NDC_PREFIX)/share/ndc/htdocs

CC      ?= cc
CFLAGS  ?= -g -O0
CFLAGS  += -fPIC \
	-I$(NDC_INCDIR) \
	-Iinclude \
	-DNDC_PREFIX=\"$(NDC_PREFIX)\" \
	-DNDC_HTDOCS=\"$(NDC_HTDOCS)\"

# LDFLAGS_LINUX   := -Wl,--version-script=libndc-mux.map
# LDFLAGS_DARWIN  := -Wl,-undefined,dynamic_lookup \
# 	-Wl,-exported_symbols_list,libndc-mux.exports

UNAME := $(shell uname -s)
ifeq ($(UNAME),Darwin)
  SO      := dylib
  LDFLAGS += $(LDFLAGS_DARWIN)
else
  SO      := so
  LDFLAGS += $(LDFLAGS_LINUX)
endif

LDFLAGS += -shared -L$(NDC_LIBDIR) -Wl,-rpath,$(NDC_LIBDIR)
LDLIBS  := -lndc -lqmap -lndx

TARGET  := libndc-mux.$(SO)
SRC     := mux.c

HTDOCS_SRC ?= ../../htdocs

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LDLIBS)

install: $(TARGET)
	mkdir -p $(INSTALL_DIR)
	cp $(HTDOCS_SRC)/* $(INSTALL_DIR)/
	mkdir -p $(NDC_INCDIR)/ttypt
	cp include/ttypt/ndc-mux.h $(NDC_INCDIR)/ttypt/ndc-mux.h

clean:
	rm -f $(TARGET)

.PHONY: all clean install
