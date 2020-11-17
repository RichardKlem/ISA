//
// Created by xklemr00 on 24.9.20.
//
#include <set>
#include <sys/socket.h>

std::set<u_int8_t> CONTENT_TYPES = {0x14, 0x15, 0x16, 0x17, 0x18};
std::set<u_int16_t> VERSIONS = {0x0300, 0x0301, 0x0302, 0x0303, 0x0304};
#include "my_tls.h"
