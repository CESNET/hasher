PKGS = glib-2.0 gnutls

CFLAGS ?= -Wall -O2

CFLAGS += $(shell pkg-config --cflags-only-other $(PKGS))
LDFLAGS += $(shell pkg-config --libs $(PKGS))
CPPFLAGS += $(shell pkg-config --cflags-only-I $(PKGS))

hasher: hasher.c
	$(CC) $(CFLAGS) $(CPPFLAGS) $< -o $@ $(LDFLAGS)

.PHONY: clean
clean:
	rm -f hasher
