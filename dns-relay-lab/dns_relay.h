#pragma once

// configs
#define LISTEN_ADDR "127.0.0.1"
#define LISTEN_PORT 53
#define UPSTREAM_ADDR "114.114.114.114"
#define UPSTREAM_PORT 53

// policies
#define MAX_EVENTS 128
#define MAX_ANSWER_COUNT 8

// buffers
#define MAX_DATAGRAM_BUFFER_SIZE 512
#define MAX_ENTRY_BUFFER_SIZE 256
#define MAX_DOMAIN_NAME_BUFFER_SIZE 256
#define MAX_IP_BUFFER_SIZE 40

// host file
#define HOST_FILE_PATH "./mappings"
