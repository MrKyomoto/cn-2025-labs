#pragma once

#include "dns_relay.h"
#include <endian.h>
#include <stdint.h>

typedef struct __attribute__((packed)) dns_header {
    unsigned id: 16;        /*%< query identification number */
#if __BYTE_ORDER == __BIG_ENDIAN
    /* fields in third byte */
    unsigned qr: 1;         /*%< response flag */
    unsigned opcode: 4;     /*%< purpose of message */
    unsigned aa: 1;         /*%< authoritative answer */
    unsigned tc: 1;         /*%< truncated message */
    unsigned rd: 1;         /*%< recursion desired */
    /* fields in fourth byte */
    unsigned ra: 1;         /*%< recursion available */
    unsigned unused: 1;     /*%< unused bits (MBZ as of 4.9.3a3) */
    unsigned ad: 1;         /*%< authentic data from named */
    unsigned cd: 1;         /*%< checking disabled by resolver */
    unsigned rcode: 4;      /*%< response code */
#endif
#if __BYTE_ORDER == __LITTLE_ENDIAN || __BYTE_ORDER == __PDP_ENDIAN
    /* fields in third byte */
    unsigned rd: 1;         /*%< recursion desired */
    unsigned tc: 1;         /*%< truncated message */
    unsigned aa: 1;         /*%< authoritative answer */
    unsigned opcode: 4;     /*%< purpose of message */
    unsigned qr: 1;         /*%< response flag */
    /* fields in fourth byte */
    unsigned rcode: 4;      /*%< response code */
    unsigned cd: 1;         /*%< checking disabled by resolver */
    unsigned ad: 1;         /*%< authentic data from named */
    unsigned unused: 1;     /*%< unused bits (MBZ as of 4.9.3a3) */
    unsigned ra: 1;         /*%< recursion available */
#endif
    /* remaining bytes */
    unsigned qdcount: 16;   /*%< number of question entries */
    unsigned ancount: 16;   /*%< number of answer entries */
    unsigned nscount: 16;   /*%< number of authority entries */
    unsigned arcount: 16;   /*%< number of resource entries */
} dns_header_t;

#define DNS_HEADER_SIZE (sizeof(dns_header_t))

typedef struct __attribute__((packed)) dns_question {
    // struct can not contain fields with variable length
    // unsigned char name[];
    uint16_t type;
    uint16_t cls;
} dns_question_t;

#define DNS_QUESTION_SIZE (sizeof(dns_question_t))

// an A record with domain name compression
typedef struct __attribute__((packed)) dns_answer_v4 {
    uint16_t name; // not real, but a pointer
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t len;
    uint32_t ip;
} dns_answer_v4_t;

#define DNS_ANSWER_v4_SIZE (sizeof(dns_answer_v4_t))

typedef struct __attribute__((packed)) dns_answer_v6 {
    uint16_t name; // not real, but a pointer
    uint16_t type;
    uint16_t cls;
    uint32_t ttl;
    uint16_t len;
    uint64_t iph; // higher bit
    uint64_t ipl; // lower bit
} dns_answer_v6_t;

#define DNS_ANSWER_v6_SIZE (sizeof(dns_answer_v6_t))

#define DNS_TYPE_A      1   // IPv4 address
#define DNS_TYPE_AAAA   28  // IPv6 address

#define DNS_CLASS_IN    1   // Internet class

#define DNS_DEFAULT_TTL 180

extern void parse_question_section(char *name, dns_question_t *question, const unsigned char *buf);
extern int try_answer_local(char ip[MAX_ANSWER_COUNT][MAX_IP_BUFFER_SIZE], const char *name, const char *file_path);
extern int transform_to_response(unsigned char *buf, int len, const char ip[MAX_ANSWER_COUNT][MAX_IP_BUFFER_SIZE], const int count, const dns_question_t *question);