#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <netinet/in.h>

void usage() {
    printf("사용법: pcap-test <interface>\n");
    printf("예시: pcap-test wlan0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

struct pcap {
    uint8_t mac_start[6];
    uint8_t mac_end[6];
    uint8_t eth_type[2];
    uint8_t ip_header[12];
    uint8_t ip_start[4];
    uint8_t ip_end[4];
    uint8_t tcp_start[2];
    uint8_t tcp_end[2];
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s) 실패: %s\n", param.dev_, errbuf);
        return -1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip and tcp", 1, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "필터 설정 오류\n");
        pcap_close(handle);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex 반환 오류 %d: %s\n", res, pcap_geterr(handle));
            break;
        }

        struct pcap* pct = (struct pcap*)packet;
        if (pct->eth_type[0] != 0x08 || pct->eth_type[1] != 0x00 || pct->ip_header[9] != 0x06)
            continue;

        printf("\nMAC 시작 주소: ");
        for (int i = 0; i < 6; i++) printf("%02x ", pct->mac_start[i]);

        printf("\nMAC 목적지 주소: ");
        for (int i = 0; i < 6; i++) printf("%02x ", pct->mac_end[i]);

        printf("\nIP 시작 주소: ");
        for (int i = 0; i < 4; i++) printf("%02x ", pct->ip_start[i]);

        printf("\nIP 목적지 주소: ");
        for (int i = 0; i < 4; i++) printf("%02x ", pct->ip_end[i]);

        printf("\nTCP 시작 포트: ");
        for (int i = 0; i < 2; i++) printf("%02x ", pct->tcp_start[i]);

        printf("\nTCP 목적지 포트: ");
        for (int i = 0; i < 2; i++) printf("%02x ", pct->tcp_end[i]);

        size_t ihl = (pct->ip_header[0] & 0x0F) * 4;
        size_t thl = (pct->tcp_start[0] >> 4) * 4;
        size_t header_len = 14 + ihl + thl;
        size_t caplen = header->caplen;
        size_t data_len = caplen > header_len ? caplen - header_len : 0;

        printf("\n데이터 길이: %zu bytes\n", data_len);
        printf("데이터: ");
        for (size_t i = 0; i < data_len && i < 20; i++)
            printf("%02x ", packet[header_len + i]);
        printf("\n");
    }

    pcap_close(handle);
    return 0;
}
