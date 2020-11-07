//
// Created by xklemr00 on 11/7/20.
//
#include <sys/socket.h>

#ifndef ISA_MY_TLS_H
#define ISA_MY_TLS_H
#define TLS_HEADER_LEN 5  //5 bajtů
#define HANDSHAKE_HEADER_LEN 1  //1 bajt


enum CONTENT_TYPE : u_int8_t {
    CHANGE_CIPHER_SPEC = 0x14,
    ALERT = 0x15,
    HANDSHAKE = 0x16,
    APPLICATION = 0x17,
    HEARTBEAT = 0x18
};

enum VERSION : u_int16_t {
    SSL30 = 0x0300,
    TLS10 = 0x0301,
    TLS11 = 0x0302,
    TLS12 = 0x0303,
    TLS13 = 0x0304
};

enum MESSAGE_TYPE : u_int8_t {
    HELLO_REQUEST = 0,
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    NEW_SESSION_TICKET = 4,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE = 11,
    SERVER_KEY_EXCHANGE = 12,
    CERTIFICATE_REQUEST = 13,
    SERVER_HELLO_DONE = 14,
    CERTIFICATE_VERIFY = 15,
    CLIENT_KEY_EXCHANGE = 16,
    FINISHED = 20
};

struct tls_header {
    CONTENT_TYPE content_type;
    VERSION version;
    u_int16_t content_length;
};
struct tls_handshake_header {
    MESSAGE_TYPE message_type;
    u_int8_t header_len = HANDSHAKE_HEADER_LEN;
    u_char *payload{};
};
struct tls_packet {
    tls_header tls_h;
    u_char *payload{};
};
#endif //ISA_MY_TLS_H
