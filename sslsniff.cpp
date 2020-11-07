//
// Created by xklemr00 on 24.9.20.
//
#include <netinet/in.h>
#include <netdb.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctime>
#include <sys/types.h>
#include </usr/include/pcap/pcap.h>
#include <getopt.h>
#include <csignal>
#include <netinet/ether.h>
#include "my_getnameinfo.h"
#include "my_string.h"
#include "my_tls.h"
#include "sslsniff.h"


//definice globálních proměnných
struct sockaddr_in sock_source_4;
struct sockaddr_in6 sock_source_6;
int tcp_count = 0, total = 0, others = 0;
char * interface_arg;
int interface_flag = 0, tcp_flag = 1, ip6_flag = 0, ip4_flag = 0, all_flag = 0,
stats_flag = 0, port_flag = 0, port_arg = 0, num_arg = 1, bytes_read = 0;
FILE * outfile = stdout;
FILE * error_outfile = stderr;

//definice dlouhých přepínačů
struct option long_options[] =
        {
                {"help", no_argument,        0, 'h'},
                {"ip6",  no_argument,        0, '6'},
                {"ip4",  no_argument,        0, '4'},
                {"all",  no_argument,        0, 'a'},
                {"stats",  no_argument,        0, 's'},
                {"num",  optional_argument,  0, 'n'},
                {"port", optional_argument,  0, 'p'},
                {0, 0, 0, 0}  // ukoncovaci prvek
        };
//definice krátkých přepínačů
char *short_options = (char*)"ht64asn:p:i:";
/**
 * @brief Funkce slouží jako koncová procedura při zachycení signálu SIGINT
 * @param unused povinně přítomný argument, není dále využit
 */
void signal_callback_handler(int unused){
    unused = unused; //obelstění překladače a jeho varování na nevyužitou proměnnou
    fprintf(outfile, "\n\n   Byl zaslán signál SIGINT, program se ukočuje.\n\n");
    exit(OK);
}

/**
 * @brief
 *      Podle dokumentace https://linux.die.net/man/3/pcap_loop musí mít tato tři argumenty
 * @param args argumenty od uživatele, v tomto programu VŽDY nullptr, dále se nevyužívá
 * @param header ukazatel na hlavičku rámce paketu
 * @param packet ukazatel na data paketu
 */
void callback(u_char * args, const struct pcap_pkthdr * header, const u_char * packet){
    args = args; //ditto parametr unused funkce signal_callback_handler()
    bytes_read = 0; //nulování počtu přečtených bajtů na 0x0000
    sa_family_t ip_version = AF_UNSPEC;
    int protocol;

    auto ether_type = (packet[12] << (unsigned int) 8) + packet[13]; //nastavení ether type z ethernetového rámce

    //Zpracování ether typu
    if (ether_type== ETH_P_IP){
        sock_source_4.sin_family = AF_INET;
        ip_version = AF_INET;
        protocol = packet[23];
    }
    else if (ether_type == ETH_P_IPV6){
        sock_source_6.sin6_family = AF_INET6;
        ip_version = AF_INET6;
        protocol = packet[20];
    }
    else{  // něco nepodporovaného
        others++;
        return;  // není třeba zpracovat, ale je potřeba inkrementovat pouze jednou
    }
    // Zpracování podle typu protokolu
    if (protocol == IPPROTO_TCP){
        tcp_count++;
        print_tcp_packet((unsigned char *) packet, header, header->len, ip_version);
     }
    else
        others++;
}

/**
 * @brief Hlavní funkce, zpracovávají se zde argumenty a připojuje se zde na rozhraní a aplikují se na něj filtry.
 * Části týkající se manipulace s rozhraním jsou inspirovány z odkazované literatury.
 * Konkrétně na webu https://www.tcpdump.org/pcap.html
 */
int main(int argc, char * argv[]) {
    signal(SIGINT, signal_callback_handler);  // zachycení SIGINT v průběhu vykonávání programu

    pcap_t * handle;
    char * dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp{};
    char filter_exp[64] = "";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    int c;
    int option_index;

    // zpracování argumentů
    if (argc > 1){
        while ((c = getopt_long(argc, argv, short_options, long_options, &option_index)) != -1)
        {
            str2int_struct_t tmp = str2int(optarg);
            str2int_struct_t *p_tmp = &tmp;

            switch (c)
            {
                case 'h':
                    fprintf(stdout,"%s", help_text);
                    exit (OK);
                case 'i':
                    interface_flag = 1;
                    interface_arg = optarg;
                    break;
                case 'p':
                    if (p_tmp->status){
                        port_flag = 1;
                        port_arg = p_tmp->num;
                    }
                    else {
                        fprintf(error_outfile, "\n%s   Nesprávný formát čísla. Zadali jste %s.%s\n\n", RED, optarg, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case 'n':
                    if (p_tmp->status){
                        if (p_tmp->num < 0){
                            fprintf(error_outfile, "\n%s   Nesprávná hodnota čísla. Zadali jste %d.%s\n\n", RED, p_tmp->num, RST);
                            exit(BAD_ARG_VALUE);
                        }
                        num_arg = p_tmp->num;
                    }
                    else{
                        fprintf(error_outfile, "\n%s   Nesprávný formát čísla. Zadali jste %s.%s\n\n", RED, optarg, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    break;
                case '6':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_outfile, "\n%s   Parametr -6 | --ip6 nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    ip6_flag = 1;
                    break;
                case '4':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_outfile, "\n%s   Parametr -4 | --ip4 nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    ip4_flag = 1;
                    break;
                case 'a':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_outfile, "\n%s   Parametr -A | --all nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    all_flag = 1;
                    break;
                case 's':
                    if (p_tmp->status == S2I_OK){
                        fprintf(error_outfile, "\n%s   Parametr -s | --stats nepřijímá žádné argumenty.%s\n\n", RED, RST);
                        exit(BAD_ARG_VALUE);
                    }
                    stats_flag = 1;
                    break;
                default:
                    exit(UNKNOWN_PARAMETER);
            }
        }
    }

    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t * interfaces, * tmp;
    int i = 0;

    if (pcap_findalldevs(&interfaces, error) == -1){
        fprintf(error_outfile, "\n%s   Nastala chyba při zjišťování dostupných rozhraní.%s\n\n", RED, RST);
        exit(INTERFACE_ERROR);
    }
    if (interface_flag == 0){
        int maxlen = 0;
        fprintf(outfile, "\n\033[0;93m Specifikujte rozhraní.%s\n Dostupná rozhraní:\n", RST);
        for(tmp = interfaces; tmp; tmp = tmp->next){
            if ((int)strlen(tmp->name) > maxlen)
                maxlen = (int)strlen(tmp->name) - maxlen;
        }
        for(tmp = interfaces; tmp; tmp = tmp->next) {
            fprintf(outfile, "   %d :  %s", i++, tmp->name);
            for (int j = maxlen - (int)strlen(tmp->name); 0 < j; j--)
                fprintf(outfile, " ");
            fprintf(outfile, " | %s\n", tmp->description);
        }
        fprintf(outfile, "\n");
        exit(OK);
    }
    else{
        bool is_valid = false;
        for(tmp = interfaces; tmp; tmp = tmp->next){
            if (strcmp(tmp->name, interface_arg) == 0){
                is_valid = true;
                break;
            }
        }
        if (!is_valid){
            fprintf(error_outfile, "\n%s   Zadané rozhraní \"%s\" není dostupné.%s\n\n", RED, interface_arg, RST);
            exit(INTERFACE_ERROR);
        }
        dev = interface_arg;
    }

    // https://linux.die.net/man/3/pcap_lookupnet
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(error_outfile, "\n%s   Nepodařilo se získat masku podsítě pro rozhraní - \"%s\".%s\n\n", RED, dev, RST);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev, BUFFER_SIZE, 1, 100, errbuf);
    if (handle == nullptr) {
        fprintf(error_outfile, "\n%s   Rozhraní \"%s\" se nepodařilo otevřít.%s\n\n", RED, dev, RST);
        exit(INTERFACE_ERROR);
    }
    // syntaxe filterů https://linux.die.net/man/7/pcap-filter
    if (ip4_flag and ip6_flag)
        sprintf(filter_exp, "(ether proto \\ip or ether proto \\ip6) and ");
    else if (ip4_flag)
        sprintf(filter_exp, "ether proto \\ip and ");
    else if (ip6_flag)
        sprintf(filter_exp, "ether proto \\ip6 and ");

    if (all_flag)
        sprintf(filter_exp, " ");  // žádný filtr, zachytává se vše
    else{
        if (port_flag)
            sprintf(filter_exp + strlen(filter_exp), "tcp port %d", port_arg);
        else
            sprintf(filter_exp + strlen(filter_exp), "tcp");
        }


    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(error_outfile, "\n   Nepodařilo se přeložit filtr \"%s\" na rozhraní \"%s\".\n\n", filter_exp, dev);
        exit(INTERFACE_ERROR);
    }

    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(error_outfile, "\n   Nepodařilo se aplikovat filtr \"%s\" na rozhraní \"%s\".\n\n", filter_exp, dev);
        exit(INTERFACE_ERROR);
    }

    // Pokud je požadovaný počet opakování == 0, úspěšně se ukončí program.
    // Funkce pcap_loop pro počet opakování == 0 cyklí "do nekonečna", tedy dokud není přerušen zvenčí.
    if (num_arg == 0)
        return OK;

    // cyklus dokud počet přijatých paketu není roven num_arg
    pcap_loop(handle, num_arg, callback, nullptr);  // https://linux.die.net/man/3/pcap_loop
    pcap_close(handle);
    if (stats_flag){
        total = tcp_count + others;
        fprintf(outfile,
                "\n  Celkový počet: ...%d\n"
                         "  TCP: .............%d\n"
                         "  Nepodporované: ...%d\n", total, tcp_count, others);
    }
    return OK;
}

/**
 * @brief Funkce vytiskne úvodní údaje:
 *          - čas přijetí paketu
 *          - zdrojová a cílová adresa(nebo jméno, pokud se adresa podaří přeložit)
 *          - zdrojový a cílový port
 * @param packet ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu, 
 *              odsud funkce získává čas přijetí paketu
 * @param source_port zdrojový port
 * @param dest_port cílový port
 */
void print_packet_preamble(unsigned char *packet, const struct pcap_pkthdr *frame, sa_family_t ip_version,
                           uint16_t source_port = 0) {
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    char * src_name_print;
    char * dest_name_print;
    char src_name[NI_MAXHOST];
    char dest_name[NI_MAXHOST];


    //získání a zpracování "časové stopy" paketu
    tm * time = localtime(&(frame->ts.tv_sec));
    int year = time->tm_year + 1900;
    int month = time->tm_mon + 1;
    int day = time->tm_mday;
    int hours = time->tm_hour;
    int minutes = time->tm_min;
    int seconds = time->tm_sec;
    long int microseconds = frame->ts.tv_usec;

    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(packet + ethhdrlen);
        ip_generic_addr addr{};
        addr.address.addr = iph->saddr;

        getnameinfo(addr, ip_version, src_name);
        src_name_print = src_name;

        addr = {};
        addr.address.addr = iph->daddr;

        getnameinfo(addr, ip_version, dest_name);
        dest_name_print = dest_name;

    }
    else if (ip_version == AF_INET6){
        auto * ip6h = (struct ip6_hdr *)(packet + ethhdrlen);
        ip_generic_addr addr{};
        addr.address.addr6 = ip6h->ip6_src;

        getnameinfo(addr, ip_version, src_name);
        src_name_print = src_name;

        addr = {};
        addr.address.addr6 = ip6h->ip6_dst;

        getnameinfo(addr, ip_version, dest_name);
        dest_name_print = dest_name;
    }
    // others
    else
        return;

    fprintf(outfile, "\n%d-%d-%d %02d:%02d:%02d.%06ld,", year, month, day, hours, minutes, seconds, microseconds);
    fprintf(outfile , "%s,%d,", src_name_print, source_port);
    fprintf(outfile , "%s,\n", dest_name_print); //TODO po te se vypise SNI
}

/**
 * @brief Funkce tiskne nejprve ethernetovou, IP a TCP hlavičku, pak jeden prázdný řádek a následně samotná data.
 * @param packet ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu,
 *              odsud funkce získává čas přijetí paketu
 * @param size celková velikost paketu
 */
void print_tcp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, int size, sa_family_t ip_version)
{
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    unsigned short iphXhdrlen;

    //IPv4
    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(packet + sizeof(struct ethhdr) );
        iphXhdrlen = (unsigned short) iph->ihl * 4;
        //IP hlavička musí mít 20-60 bajtů
        if (iphXhdrlen < 20 or iphXhdrlen > 60) {
            fprintf(error_outfile,"\n   Neplatná délka IPv4 hlavičky, délka = %u bajtů\n", iphXhdrlen);
            exit(PACKET_ERROR);
        }
    }
    //musí být IPv6, jiná hodnota se do funkce nemůže dostat
    else
        iphXhdrlen = 40;

    auto * tcph = (struct tcphdr *)(packet + iphXhdrlen + ethhdrlen);

    //doff = data offset, horní 4 bity 46.bajtu, násobeno 4, protože se jedná o počet 32-bitových slov, 32bitů = 4bajtů
    //viz https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    int tcphdrlen = tcph->doff * 4;
    int header_size = ethhdrlen + iphXhdrlen + tcphdrlen;

    auto * tlshdr = (struct tls_header *)(packet + header_size);

    if (tlshdr->content_type == HANDSHAKE){
        auto * tls_handshake_header = (struct tls_handshake_header *) packet + header_size + TLS_HEADER_LEN;
        if (tls_handshake_header->message_type == CLIENT_HELLO)
            printf("%02X %02X", tls_handshake_header->payload[116-5], tls_handshake_header->payload[117-5]);
    }

    print_packet_preamble(packet, frame, ip_version, ntohs(tcph->source));



    fprintf(outfile , "\n");
    //print_data(packet, header_size);
    fprintf(outfile , "\n");
    //print_data(packet + header_size, size - header_size);
    fprintf(outfile , "\n");
}

/**
 * @brief Vytiskne číslo v hexadecimálním tvaru s fixní délkou 4 s vyplňujícími nulami před číslem
 * @param size číslo, které se má vytisknout
 */
void print_bytes(int size){
    fprintf(outfile, "0x%04x", size);
}
