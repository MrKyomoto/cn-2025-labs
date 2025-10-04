CC = gcc
CFLAGS = -O2 -Wall -Wextra -Werror

SRCS = dns_relay.c dns_dgram_utils.c
HEADERS = dns_relay.h dns_dgram_utils.h
OBJS = $(SRCS:.c=.o)
TARGET = dns_relay

all: $(TARGET)

run: $(TARGET)
	sudo ./$(TARGET)

$(TARGET): $(OBJS) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

clean:
	rm -f $(OBJS) $(TARGET)

.PHONY: all clean run

.SUFFIXES: .c .o

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@