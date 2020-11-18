//
// Created by Richard Klem on 23.04.20.
//
#include <cstdint>
#include <sys/socket.h>
#include "my_string.h"


#ifndef PROJ2_PROJ_H
#define PROJ2_PROJ_H

#define YELLOW "\033[0;93m"
#define RED "\033[0;91m"
#define RST "\033[0m"

int BUFFER_SIZE = 65536;
const char * help_text = "\n***Nápověda k snifferu paketů***\n"
                   "  Možné parametry:\n"
                   "    -i nazev_rozhrani (Rozhraní, na kterém se bude poslouchat.\n"
                   "            Nebude-li tento parametr uveden, vypíše se seznam aktivních rozhraní)\n"
                   "    -p int:cislo_portu (Sniffer bude zachytávat pakety pouze na daném portu,\n"
                   "            nebude-li tento parametr uveden, uvažují se všechny porty)\n"
                   "    -t | --tcp (bude zobrazovat pouze tcp pakety)\n"
                   "    -n | --num int:pocet_paketu (Určuje počet vypsaných paketů,\n"
                   "        pokud nebude počet specifikován, vypíše se pouze 1 paket.)\n"
                   "    -6 | --ip6 (Filtruje IPv6 protokol, lze kombinovat s IPv4, tcp, udp a port filtrováním.)\n"
                   "    -4 | --ip4 (Filtruje IPv6 protokol, lze kombinovat s IPv6, tcp, udp a port filtrováním.)\n"
                   "    -a | --all (Nefiltruje se nic, zachytávají se všechny pakety, vypisují se pouze podporované.)\n"
                   "    -s | --stats (Výpis statistik o síťovém provozu na konci běhu programu.)\n"
                   "  Krátké parametry je možné zadávat ve tvaru \"-n5\" anebo \"-n 5\".\n"
                   "  Dlouhé parametry je nutné zadávat ve tvaru \"--num=5\".\n\n";

enum EXIT_CODES {OK = 0,
                 INTERFACE_ERROR = 1,
                 SOCKET_ERROR = 2,
                 PACKET_ERROR = 3,
                 BAD_ARG_VALUE = 11,
                 UNKNOWN_PARAMETER = 12};


void signal_callback_handler(int unused);
void callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet);
void process_tcp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, sa_family_t ip_version);
tcp_stream * get_stream(const char *src_to_print, const char *dst_to_print, const tcphdr *tcph);
char * get_TLS_SNI(unsigned char *bytes, int* len);
void process_payload(const unsigned char *packet, const pcap_pkthdr *frame, int header_size, tcp_stream *tcp_stream_p);

#endif //PROJ2_PROJ_H
