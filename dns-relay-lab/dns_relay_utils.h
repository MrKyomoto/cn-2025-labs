#pragma once

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>

typedef struct client_info {
    struct sockaddr_in addr;
    // required to be initialized to sizeof(addr)
    socklen_t len;
} client_info_t;

// return a pointer to a static epoll_event struct for the given listen_fd
static struct epoll_event * listen_event(int listen_fd) {
    static struct epoll_event event;
    event.events = EPOLLIN;
    event.data.fd = listen_fd;
    return &event;
}

// fatal error is unrecoverable, exit the program
static void handle_fatal(const char *msg) {
    perror(msg);
    exit(1);
}

// send a new datagram (buf, len) 
// to client (client_info) 
// through specific socket (fd)
static inline void send_datagram(int fd, unsigned char *buf, int len, client_info_t client_info) {
    sendto(fd, buf, len, 0, (struct sockaddr *) &client_info.addr, client_info.len);
}

// if find answer in local host file, type = "local resolve"
// if relay to upstream, type = "relay"
static inline void log_result(const char *type, const char *name) {
    printf("query %s, handled as %s\n", name, type);
}