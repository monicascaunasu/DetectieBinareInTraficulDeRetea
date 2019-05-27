/**
 * interceptare trafic
 * Scaunasu Monica
 * Gombar Izabella
 */
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <ctype.h>

void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)

{
    
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    } 

	const unsigned char* ipHdr;
	int ipLength = 0;
	struct ether_header* ether_pointer = (struct ether_header*) packet;
	const int ethernet_header_length=14;
	if (ntohs(ether_pointer) == ETHERTYPE_IP) {
		ipHdr = packet + ethernet_header_length;
		ipLength = (*(ipHdr) & 0x0F);
	}
	
    
    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);
}

void search_binary(const unsigned char* p_payload, int payloadLen) {
	int found = 0;
	
	for (int i=0; i< payloadLen-4; i++) {

		if (p_payload[i] == 0x7F && p_payload[i+1] == 0x45 && p_payload[i+2] == 0x4C && p_payload[i+3] == 0x46) {
			fprintf(stdout, "Am gasit executabil ELF la adresa %p!\n", p_payload + i);
		}

	}

	for (int i=0; i< payloadLen-2; i++) {
		if (p_payload[i] == 0x4D && p_payload[i+1] == 0x5A)
			fprintf(stdout, "Am gasit executabil PE(MZ) la adresa %p\n", p_payload + i);
		if (p_payload[i] == 0x5A && p_payload[i+1] == 0x4D)
			fprintf(stdout, "Am gasit executabil PE(ZM) la adresa %p\n", p_payload + i);
	}
}

void print_packet_info(const u_char *packet, struct pcap_pkthdr* packet_header) {

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    
    int ethernet_header_length = 14; 
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    
    ip_header = packet + ethernet_header_length;
   
    ip_header_length = ((*ip_header) & 0x0F);
    
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

   
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        printf("Not a TCP packet. Skipping...\n\n");
        return;
    }


    tcp_header = packet + ethernet_header_length + ip_header_length;

    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;

    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    
    int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = packet_header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", payload);

	search_binary(payload, payload_length);

    
    
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
		if (isprint(*temp_pointer))
            		printf("%c", *temp_pointer);
		else
			printf(".");
            temp_pointer++;
        }
        printf("\n");
    }
    
    return;
}

int main(int argc, char **argv[]) {

	char *device = "ens33";
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
	int snapshot_length = 1024;
    int timeout_limit = 10000; 
	int total_packet_count;
    device = pcap_lookupdev(error_buffer);
    if (device == NULL) {
        printf("Error finding device: %s\n", error_buffer);
        return 1;
    }

    
    handle = pcap_open_live(
            device,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );
    if (handle == NULL) {
         fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
         return 2;
     }
    
    printf("Merge \n");
    total_packet_count = pcap_loop(handle, 0, my_packet_handler, NULL);

    pcap_close(handle);


   

    return 0;
   
}

