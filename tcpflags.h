#ifndef TCPFLAGS_H
#define TCPFLAGS_H

#include <stdint.h>

int translate_tcp_flag(const char *name, uint32_t *val);
const char *name_from_tcp_flag(uint32_t flag);
void list_from_tcp_flags(uint32_t flag, char *str);

#endif
