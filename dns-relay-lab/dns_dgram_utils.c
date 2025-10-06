#include "dns_dgram_utils.h"
#include "dns_relay.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

int parse_question_name(char *name, int offset, const unsigned char *buf) {
  int total_bytes = 0;
  int name_index = 0;
  while (1) {
    char byte_buffer = buf[offset];

    if ((byte_buffer & 0xC0) == 0xC0) {
      int ptr_offset = ((byte_buffer & 0x3F) << 8) | buf[offset + 1];
      offset += 2;
      parse_question_name(name + name_index, ptr_offset, buf);
      break;
    } else if (byte_buffer == '\0') {
      total_bytes += 1;
      offset += 1;
      break;
    } else {
      total_bytes += 1 + byte_buffer;
      offset += 1;

      for (int i = 0; i < byte_buffer; i++) {
        name[name_index] = buf[offset + i];
        name_index++;
      }
      name[name_index] = '.';
      name_index++;
      offset += byte_buffer;
    }
  }
  if (name_index > 0 && name[name_index - 1] == '.') {
    name_index--;
  }
  name[name_index] = '\0';

  return total_bytes;
}

/*
    parse the domain name, type and class from question section of a dns
   datagram input: buf: the pointer point to the begin of the dns datagram
    output:
        name: the resolved domain name
        question: other fields except domain name in question section
    note: support both sequences of labels and pointer
*/
void parse_question_section(char *name, dns_question_t *question,
                            const unsigned char *buf) {
  // NOTE: header len is fixed 12 bytes
  int offset = 12;
  int name_len = parse_question_name(name, offset, buf);
  offset += name_len;

  question->type = ntohs(*(uint16_t *)(buf + offset));
  question->cls = ntohs(*(uint16_t *)(buf + offset + 2));

  return;
}

/**
    try to find answer to the domain name by reading the local host file
    input:
        name: the domain name try to answer
        question: other fields except domain name in question section
        file_path: the path to the local host file
    output:
        ip: the IP of multiple resource records in string format (eg.
   "192.168.1.1") return: 0 if no record, positive if any record note: supports
   one IP mapping to multiple domain names per line
*/
int parse_line(char *ip_buf, char name_buf[][128], char *line_buf) {
  char *ptr = line_buf;
  while (isspace((unsigned char)*ptr)) {
    ptr++;
  }

  if (*ptr == '\0' || *ptr == '#' || *ptr == '\n') {
    return 0;
  }

  if (('0' <= *ptr && *ptr <= '9') || *ptr == ':') {
    // NOTE: parse it
    char *ip_end = ptr;
    while (!isspace((unsigned char)*ip_end) && *ip_end != '\0' &&
           *ip_end != '#' && *ip_end != '\n') {
      ip_end++;
    }
    int ip_len = ip_end - ptr;
    if (ip_len <= 0 || ip_len >= MAX_IP_BUFFER_SIZE) {
      return 0;
    }
    strncpy(ip_buf, ptr, ip_len);
    ip_buf[ip_len] = '\0';

    ptr = ip_end;
    while (isspace((unsigned char)*ptr)) {
      ptr++;
    }

    int name_index = 0;
    while (*ptr != '\0' && *ptr != '#' && *ptr != '\n' && name_index < 8) {
      while (isspace((unsigned char)*ptr)) {
        ptr++;
      }
      if (*ptr == '\0' || *ptr == '#' || *ptr == '\n') {
        break;
      }

      char *name_end = ptr;
      while (!isspace((unsigned char)*name_end) && *name_end != '\0' &&
             *name_end != '#' && *name_end != '\n') {
        name_end++;
      }
      int name_len = name_end - ptr;
      if (name_len > 0 && name_len < 128) {
        strncpy(name_buf[name_index], ptr, name_len);
        name_buf[name_index][name_len] = '\0';
        name_index++;
      }

      ptr = name_end;
    }
    return 1;
  } else {
    // this line is not a valid ip line
    return 0;
  }
}
int try_answer_local(char ip[MAX_ANSWER_COUNT][MAX_IP_BUFFER_SIZE],
                     const char *name, const char *file_path) {
  FILE *fp = fopen(file_path, "r");
  if (fp == NULL) {
    perror("Failed to open file");
    return -1;
  }

  char line_buf[1024];
  int ip_count = 0;
  while (1) {
    char *result = fgets(line_buf, sizeof(line_buf), fp);
    if (result == NULL) {
      break;
    }
    char ip_buf[MAX_IP_BUFFER_SIZE];
    char name_buf[8][128] = {0};
    if (parse_line(ip_buf, name_buf, line_buf) != 1) {
      continue;
    }

    for (int i = 0; i < 8 && name_buf[i][0] != '\0'; i++) {
      if (strcmp(name_buf[i], name) == 0) {
        if (ip_count < MAX_ANSWER_COUNT) {
          strncpy(ip[ip_count], ip_buf, MAX_IP_BUFFER_SIZE - 1);
          ip[ip_count][MAX_IP_BUFFER_SIZE - 1] = '\0';
          ip_count++;
        }
        break;
      }
    }
  }
  return ip_count;
}

/**
    it's more convenient to transform a dns request datagram to a dns response
   datagram than to construct a new dns response datagram
    input:
      buf: original dns request datagram
      len: original dns request datagram length
      ip: the IP of multiple resource records in string format(eg."192.168.1.1")
      count: how many IP bind to this domain name
      question: other fields except domain name in question section
  output:
      buf: new dns response datagram return: length of thenew dns response
  datagram note:
        - do not need domain name, use pointer instead
        - need to support both IPv4 and IPv6
 */
inline int get_ip_type(const char *ip) {
  int type_flag = 0;
  for (int i = 0; ip[i] != '\0'; i++) {
    if (ip[i] == '.') {
      type_flag = 1;
      break;
    } else if (ip[i] == ':') {
      type_flag = 2;
      break;
    }
  }

  return type_flag;
}
// MEMO: 我感觉这个question param应该是在转换ip的时候用到的，因为question里有ip
// type，可以根据这个直接转换，但我选择写了个函数判断ip是什么样的类型
int transform_to_response(unsigned char *buf, int len,
                          const char ip[MAX_ANSWER_COUNT][MAX_IP_BUFFER_SIZE],
                          int count, const dns_question_t *question) {
  if (buf == NULL || len < 12 || count <= 0 || count > MAX_ANSWER_COUNT) {
    return len;
  }
  dns_header_t *header = (dns_header_t *)buf;
  header->qr = 1;
  header->ra = 1;
  header->rcode = 0;
  header->ancount = htons(count);
  header->nscount = 0;
  header->arcount = 0;

  unsigned char *answer_start = buf + len;
  int response_len = len;

  for (int i = 0; i < count; i++) {
    const char *ip_ptr = ip[i];
    int ip_type = get_ip_type(ip_ptr);
    if (ip_type == 0) {
      continue;
    }

    if (ip_type == DNS_TYPE_A) {
      dns_answer_v4_t *ans = (dns_answer_v4_t *)answer_start;
      ans->name = htons(0xC00C);
      ans->type = htons(DNS_TYPE_A);
      ans->cls = htons(DNS_CLASS_IN);
      ans->ttl = htonl(DNS_DEFAULT_TTL);
      ans->len = htons(4);

      struct in_addr addr;
      inet_pton(AF_INET, ip_ptr, &addr);
      ans->ip = addr.s_addr;

      response_len += DNS_ANSWER_v4_SIZE;
      answer_start += DNS_ANSWER_v4_SIZE;
    } else {
      dns_answer_v6_t *ans = (dns_answer_v6_t *)answer_start;
      ans->name = htons(0xC00C);
      ans->type = htons(DNS_TYPE_AAAA);
      ans->cls = htons(DNS_CLASS_IN);
      ans->ttl = htonl(DNS_DEFAULT_TTL);
      ans->len = htons(16);

      struct in6_addr addr6;
      inet_pton(AF_INET6, ip_ptr, &addr6);
      memcpy(&ans->iph, &addr6.s6_addr[0], 8);
      memcpy(&ans->ipl, &addr6.s6_addr[8], 8);

      response_len += DNS_ANSWER_v6_SIZE;
      answer_start += DNS_ANSWER_v6_SIZE;
    }
  }
  return response_len;
}
