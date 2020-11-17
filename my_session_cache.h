//
// Created by xklemr00 on 7-11-20.
//
#include <cstdint>
#include <netinet/in.h>
#include <ctime>

#ifndef ISA_MY_SESSION_CACHE_H
#define ISA_MY_SESSION_CACHE_H

struct ip_generic_addr{
    union {
        uint32_t addr;
        struct in6_addr addr6;
    } address;
};

struct tls_stream{
    uint32_t bytes = 0;
    char * sni{};  // SNI může být téměř libovolně dlouhé
    bool client_hello = false;
    bool server_hello = false;

    bool bye = false;


};

struct tcp_stream{
    uint32_t packets = 0;
    timeval start_time{};
    timeval end_time{};
    uint32_t duration = 0;
    char * client_ip{};
    char * server_ip{};
    uint32_t client_port{};
    uint32_t server_port{};
    tls_stream tlsStream;
    uint32_t client_first_seq{};
    uint32_t client_last_seq{};
    uint32_t client_last_ack{};
    uint32_t server_first_seq{};
    uint32_t server_last_seq{};
    uint32_t server_last_ack{};
    bool client_fin = false;
    bool server_fin = false;
};

extern std::vector<tcp_stream> tcp_streams;

#endif //ISA_MY_SESSION_CACHE_H
