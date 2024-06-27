TARGET := gfal_plugin_hercules.so

CC := cc
CFLAGS = -O2 -std=c99 -fPIC
CFLAGS += -Wall -Wextra
CFLAGS += -I/usr/local/include/gfal2 -I/usr/include/glib-2.0 -I/usr/lib64/glib-2.0/include

## for debugging:
CFLAGS += -g3

LDFLAGS := -shared -lgfal2 -lgfal_transfer -lglib-2.0 -lcurl
DEPFLAGS := -MP -MD

SRCS := $(wildcard *.c)
OBJS := $(SRCS:.c=.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all
all: $(TARGET)

ifndef PREFIX
PREFIX := /usr/local
endif
ifndef SYSCONFDIR
SYSCONFDIR := $(PREFIX)/etc
endif

.PHONY: install
install: $(TARGET)
# Fail if target directories don't exist (gfal is probably installed elsewhere)
	install $(TARGET) $(PREFIX)/lib64/gfal2-plugins/
	install -m 444 README_PLUGIN_HERCULES $(PREFIX)/share/doc/gfal2/
	install -m 644 hercules_plugin.conf $(SYSCONFDIR)/gfal2.d/


$(TARGET): $(OBJS)
	$(CC) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) $(DEPFLAGS) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -rf $(TARGET) $(OBJS) $(DEPS)

-include $(DEPS)
