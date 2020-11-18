/**
 * @author: Richard Klem
 * @email: xklemr00@stud.fit.vutbr.cz
 * @login: xklemr00
 */
#include <cstdint>
#include <netinet/in.h>
#include <ctime>

#ifndef ISA_MY_SESSION_CACHE_H
#define ISA_MY_SESSION_CACHE_H


struct tls_stream{
    uint32_t bytes = 0;
    char * sni{};  // SNI může být téměř libovolně dlouhé
    bool client_hello = false;
    bool server_hello = false;
};

struct tcp_stream{
    uint32_t packets = 0;
    timeval start_time{};
    timeval end_time{};
    char * client_ip{};
    char * server_ip{};
    uint32_t client_port{};
    uint32_t server_port{};
    tls_stream tlsStream;
    bool client_fin = false;
};

extern std::vector<tcp_stream> tcp_streams;

#endif //ISA_MY_SESSION_CACHE_H
