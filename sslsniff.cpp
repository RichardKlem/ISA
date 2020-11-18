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
//#include <ctime>
#include <sys/types.h>
#include </usr/include/pcap/pcap.h>
#include <getopt.h>
#include <csignal>
#include <exception>
#include <netinet/ether.h>
#include <vector>
#include <algorithm>
#include <string>
#include "my_string.h"
#include "my_session_cache.h"
#include "my_tls.h"
#include "sslsniff.h"




//definice globálních proměnných
struct sockaddr_in sock_source_4;
struct sockaddr_in6 sock_source_6;
int tcp_count = 0, total = 0, others = 0;
char * interface_arg;
char * captured_file_arg;
int interface_flag = 0, captured_file_flag = 0, tcp_flag = 1, ip6_flag = 0, ip4_flag = 0, all_flag = 0,
stats_flag = 0, port_flag = 0, port_arg = 0, num_arg = -1, bytes_read = 0;
FILE * outfile = stdout;
FILE * error_outfile = stderr;

//definice dlouhých přepínačů
struct option long_options[] =
        {
                {"help",   no_argument,        0, 'h'},
                {"ip6",    no_argument,        0, '6'},
                {"ip4",    no_argument,        0, '4'},
                {"all",    no_argument,        0, 'a'},
                {"stats",  no_argument,        0, 's'},
                {"num",    optional_argument,  0, 'n'},
                {"port",   optional_argument,  0, 'p'},
                {0, 0, 0, 0}  // ukoncovaci prvek
        };

//definice krátkých přepínačů
char *short_options = (char*)"h64asn:p:i:r:";
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
    // Zajímají mě pouze TCP pakety
    if (protocol == IPPROTO_TCP){
        tcp_count++;
        process_tcp_packet((unsigned char *) packet, header, header->len, ip_version);
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
                case 'r':
                    captured_file_flag = 1;
                    captured_file_arg = optarg;
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
    int find_device_result = pcap_findalldevs(&interfaces, error);

    if (!interface_flag and !captured_file_flag){
        int i = 0;
        int maxlen = 0;
        fprintf(outfile, "\n%sSpecifikujte rozhraní: 'sudo ./sslsniff -i <nazev_rozhrani>' nebo soubor se zachycenou "
                         "komunikací 'sudo ./sslsniff -r <nazev_souboru.pcapng>'.%s\n Dostupná rozhraní:\n", YELLOW, RST);
        if (find_device_result  == -1){
            fprintf(error_outfile, "\n%s   Nastala chyba při zjišťování dostupných rozhraní.%s\n\n", RED, RST);
            exit(INTERFACE_ERROR);
        }
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
    else if (interface_flag){
        if (find_device_result  == -1){
            fprintf(error_outfile, "\n%s   Nastala chyba při zjišťování dostupných rozhraní.%s\n\n", RED, RST);
            exit(INTERFACE_ERROR);
        }
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
    else {  // Zpracování pcapng souboru
        handle = pcap_open_offline(captured_file_arg, errbuf);
        if (nullptr == handle){
            fprintf(error_outfile, "\n   Nepodařilo se otevřít soubor '%s'.\n\n", captured_file_arg);
            exit(BAD_ARG_VALUE);
        }
        pcap_loop(handle, num_arg, callback, nullptr);  // https://linux.die.net/man/3/pcap_loop
    }
}

/**
 * @brief Funkce tiskne nejprve ethernetovou, IP a TCP hlavičku, pak jeden prázdný řádek a následně samotná data.
 * @param packet ukazatel na pole obsahující data příchozího paketu
 * @param frame ukazatel na strukturu představující zaobalující rámec celého paketu,
 *              odsud funkce získává čas přijetí paketu
 * @param size celková velikost paketu
 */
void process_tcp_packet(unsigned char * packet, const struct pcap_pkthdr * frame, int size, sa_family_t ip_version)
{
    unsigned short ethhdrlen = sizeof(struct ethhdr);
    unsigned short iphXhdrlen;
    tcp_stream tmp_tcp_stream;

    //struct sockaddr_in src{};
    char *src_to_print;
    //struct sockaddr_in dst{};
    char * dst_to_print;
    char src_name[NI_MAXHOST];
    char dest_name[NI_MAXHOST];

    // IPv4
    if (ip_version == AF_INET){
        auto * iph = (struct iphdr *)(packet + sizeof(struct ethhdr) );
        iphXhdrlen = (unsigned short) iph->ihl * 4;
        //IP hlavička musí mít 20-60 bajtů
        if (iphXhdrlen < 20 or iphXhdrlen > 60) {
            fprintf(error_outfile,"\n   Neplatná délka IPv4 hlavičky, délka = %u bajtů\n", iphXhdrlen);
            exit(PACKET_ERROR);
        }
        inet_ntop(ip_version, &(iph->saddr), src_name, INET_ADDRSTRLEN);
        src_to_print = src_name;
        inet_ntop(ip_version, &(iph->daddr), dest_name, INET_ADDRSTRLEN);
        dst_to_print = dest_name;
    }
    // Musí být IPv6, jiná hodnota se do funkce nemůže dostat.
    else{
        iphXhdrlen = 40;
        auto * ip6h = (struct ip6_hdr *)(packet + ethhdrlen);

        inet_ntop(ip_version, &(ip6h->ip6_src), src_name, INET6_ADDRSTRLEN);
        src_to_print = src_name;
        inet_ntop(ip_version, &(ip6h->ip6_dst), dest_name, INET6_ADDRSTRLEN);
        dst_to_print = dest_name;
    }
    auto * tcph = (struct tcphdr *)(packet + iphXhdrlen + ethhdrlen);

    //doff = data offset, horní 4 bity 46.bajtu, násobeno 4, protože se jedná o počet 32-bitových slov, 32bitů = 4bajtů
    //viz https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    int tcphdrlen = tcph->doff * 4;
    int header_size = ethhdrlen + iphXhdrlen + tcphdrlen;


    //tcp_stream tcpStream;
    tcp_stream * tcp_stream_p;
    // Client SYN požadavek
    if (tcph->syn and !tcph->ack){
        tcp_stream_p = get_stream(src_to_print, dst_to_print, tcph);
        if (tcp_stream_p == nullptr){
            tmp_tcp_stream.packets++;
            tmp_tcp_stream.client_ip = strdup(src_to_print);
            tmp_tcp_stream.server_ip = strdup(dst_to_print);
            tmp_tcp_stream.client_port = ntohs(tcph->source);
            tmp_tcp_stream.server_port = ntohs(tcph->dest);
            tmp_tcp_stream.client_first_seq = tcph->th_seq;
            tmp_tcp_stream.client_last_seq = tmp_tcp_stream.client_first_seq;
            tmp_tcp_stream.start_time = frame->ts;
            tcp_streams.push_back(tmp_tcp_stream);
        }
        else {
            tcp_stream_p->packets++;
        }
    }
    // Server SYN, ACK odpověď
    else if (tcph->syn and tcph->ack){
        tcp_stream_p = get_stream(src_to_print, dst_to_print, tcph);
        if (tcp_stream_p != nullptr){
            tcp_stream_p->packets++;
        }
    }
    // FIN
    else if(tcph->fin){
        tcp_stream_p = get_stream(src_to_print, dst_to_print, tcph);
        if (tcp_stream_p != nullptr){
            if (!tcp_stream_p->client_fin){
                tcp_stream_p->client_fin = true;
                tcp_stream_p->packets++;
                process_payload(packet, frame, header_size, tcp_stream_p);
            }
            else{
                process_payload(packet, frame, header_size, tcp_stream_p);

                tcp_stream_p->packets++;
                tcp_stream_p->end_time = frame->ts;
                timeval time_div{};
                timersub(&(tcp_stream_p->end_time), &(tcp_stream_p->start_time), &time_div);
                //získání a zpracování "časové stopy" paketu
                tm * time = localtime(&(tcp_stream_p->start_time.tv_sec));
                int year = time->tm_year + 1900;
                int month = time->tm_mon + 1;
                int day = time->tm_mday;
                int hours = time->tm_hour;
                int minutes = time->tm_min;
                int seconds = time->tm_sec;
                long int microseconds = tcp_stream_p->start_time.tv_usec;
                if (tcp_stream_p->tlsStream.bytes > 0 and tcp_stream_p->tlsStream.client_hello and tcp_stream_p->tlsStream.server_hello) {
                    fprintf(outfile, "%04d-%02d-%02d %02d:%02d:%02d.%06ld,", year, month, day, hours, minutes, seconds, microseconds);
                    fprintf(outfile, "%s,%d,", tcp_stream_p->client_ip, tcp_stream_p->client_port);
                    fprintf(outfile, "%s,%s,", tcp_stream_p->server_ip, tcp_stream_p->tlsStream.sni);
                    fprintf(outfile, "%d,%d,", tcp_stream_p->tlsStream.bytes, tcp_stream_p->packets);
                    fprintf(outfile, "%ld.%06ld\n", time_div.tv_sec, time_div.tv_usec);
                }
                tcp_streams.erase((std::vector<tcp_stream>::iterator )tcp_stream_p);
            }
        }
    }
    // RST
    else if(tcph->rst){
        tcp_stream_p = get_stream(src_to_print, dst_to_print, tcph);
        if (tcp_stream_p != nullptr){
            process_payload(packet, frame, header_size, tcp_stream_p);

            tcp_stream_p->packets++;
            tcp_stream_p->end_time = frame->ts;
            timeval time_div{};
            timersub(&(tcp_stream_p->end_time), &(tcp_stream_p->start_time), &time_div);
            //získání a zpracování "časové stopy" paketu
            tm * time = localtime(&(tcp_stream_p->start_time.tv_sec));
            int year = time->tm_year + 1900;
            int month = time->tm_mon + 1;
            int day = time->tm_mday;
            int hours = time->tm_hour;
            int minutes = time->tm_min;
            int seconds = time->tm_sec;
            long int microseconds = tcp_stream_p->start_time.tv_usec;
            if (tcp_stream_p->tlsStream.bytes > 0 and tcp_stream_p->tlsStream.client_hello and tcp_stream_p->tlsStream.server_hello){
                fprintf(outfile, "%04d-%02d-%02d %02d:%02d:%02d.%06ld,", year, month, day, hours, minutes, seconds, microseconds);
                fprintf(outfile , "%s,%d,", tcp_stream_p->client_ip, tcp_stream_p->client_port);
                fprintf(outfile , "%s,%s,", tcp_stream_p->server_ip, tcp_stream_p->tlsStream.sni);
                fprintf(outfile , "%d,%d,", tcp_stream_p->tlsStream.bytes, tcp_stream_p->packets);
                fprintf(outfile , "%ld.%06ld\n", time_div.tv_sec, time_div.tv_usec);
            }
            tcp_streams.erase((std::vector<tcp_stream>::iterator )tcp_stream_p);
        }
    }
    // Ostatni pakety
    else{
        tcp_stream_p = get_stream(src_to_print, dst_to_print, tcph);
        if (tcp_stream_p != nullptr){
            tcp_stream_p->packets++;

            process_payload(packet, frame, header_size, tcp_stream_p);
        }
    }
}

void process_payload(const unsigned char *packet, const pcap_pkthdr *frame, int header_size, tcp_stream *tcp_stream_p) {
    uint32_t payload_len = frame->len - header_size;
    auto * payload = (unsigned char *) (packet + header_size);
    for(int i = 0; ((i + 4) < payload_len)  and (payload_len > 6); i++){
        uint8_t content_type = payload[i];
        uint16_t version = payload[i + 1] * 256 + payload[i + 2];
        uint16_t content_len = payload[i + 3] * 256 + payload[i + 4];
        if (CHANGE_CIPHER_SPEC <= content_type and content_type <= HEARTBEAT and
            SSL30 <= version and version <= TLS13){
            tcp_stream_p->tlsStream.bytes += content_len;
            i += content_len;
        }
    }
    auto * tlshdr = (struct tls_header *)(packet + header_size);
    if ((uint8_t) tlshdr->content_type == HANDSHAKE) {
        auto * tls_handshake_header = (struct tls_handshake_header *) (packet + header_size + TLS_HEADER_LEN);
        if (tls_handshake_header->message_type == CLIENT_HELLO) {
            tcp_stream_p->tlsStream.client_hello = true;
            int len;
            tcp_stream_p->tlsStream.sni = strdup(get_TLS_SNI((unsigned char *) tlshdr, &len));
        }
        else if(tls_handshake_header->message_type == SERVER_HELLO){
            tcp_stream_p->tlsStream.server_hello = true;
        }
    }
}

tcp_stream * get_stream(const char *src_to_print, const char *dst_to_print, const tcphdr *tcph) {
    for (auto &el : tcp_streams){
        // Když sedí IP a porty serveru ke klientovi
        if (((!strcmp(el.client_ip, dst_to_print)) and
              (!strcmp(el.server_ip, src_to_print)) and
              (el.client_port == ntohs(tcph->dest)) and
              (el.server_port == ntohs(tcph->source))) or
             (((!strcmp(el.client_ip, src_to_print)) and
               (!strcmp(el.server_ip, dst_to_print)) and
               (el.client_port == ntohs(tcph->source)) and
               (el.server_port == ntohs(tcph->dest))
             ))) {
            return &el;
        }
    }
    return nullptr;
}

struct MyException : public std::exception {
    const char * what () const noexcept override {
        return "Incomplete SSL Client Hello";
    }
};

char * get_TLS_SNI(unsigned char *bytes, int* len)
{
    unsigned char *curr;
    unsigned char sidlen = bytes[43];
    curr = bytes + 1 + 43 + sidlen;
    unsigned short cslen = ntohs(*(unsigned short*)curr);
    curr += 2 + cslen;
    unsigned char cmplen = *curr;
    curr += 1 + cmplen;
    unsigned char *maxchar = curr + 2 + ntohs(*(unsigned short*)curr);
    curr += 2;
    unsigned short ext_type = 1;
    unsigned short ext_len;
    while(curr < maxchar && ext_type != 0)
    {
        ext_type = ntohs(*(unsigned short*)curr);
        curr += 2;
        ext_len = ntohs(*(unsigned short*)curr);
        curr += 2;
        if(ext_type == 0)
        {
            curr += 3;
            unsigned short namelen = ntohs(*(unsigned short*)curr);
            curr += 2;
            *len = namelen;
            return (char*)curr;
        }
        else curr += ext_len;
    }
    if (curr != maxchar) throw MyException();

    return (char *)""; //SNI was not present
}
