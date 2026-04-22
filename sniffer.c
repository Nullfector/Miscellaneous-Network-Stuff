#include <stdio.h>
#include <pcap.h>
#include <time.h>

int welcome(pcap_if_t** chosen_dev, pcap_if_t* alldevs){

    *chosen_dev = alldevs;
    unsigned devid = 0, choice;
    printf("Available devices:\n-----------------------\n");
    while(*chosen_dev != NULL){
        printf("ID = [%u] | Name: %s - %s\n",devid++,(*chosen_dev)->name, (*chosen_dev)->description ? (*chosen_dev)->description : "No description");
        *chosen_dev = (*chosen_dev)->next;
    }
    printf("Choose the device:");
    scanf("%u",&choice);

    if(choice > devid){
        printf("????");
        return -1;
    }

    *chosen_dev = alldevs;
    for(int i=0;i<choice;i++){
        *chosen_dev = (*chosen_dev)->next;
    }
    printf("%s chosen\n", (*chosen_dev)->name);
    return 0;
}


//gcc sniffer.c -Wall -I"C:/libs/npcap/Include" -L"C:/libs/npcap/Lib/x64" -lws2_32 -lwpcap -lPacket -o sniff.exe
int main(int argc, char* argv[]){
    char err[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs, *curdev;

    if(pcap_findalldevs(&alldevs, err) == 1){
        printf("error");
        return -1;
    }

    if(welcome(&curdev, alldevs) == -1) return -1;

    pcap_t* handle = pcap_open_live(curdev->name,65536,1,1000,err);
    const u_char* packet;
    struct pcap_pkthdr* header;

    char time_buf[64], l2_buf[64];
    int counter = 0;
    time_t sec;
    struct tm *tl;
    int l2class = pcap_datalink(handle), packet_code;
    while((packet_code = pcap_next_ex(handle, &header, &packet))==1){
        sec = header->ts.tv_sec;
        tl = localtime(&sec);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tl);

        switch(l2class){
        case 0:
            strcpy(l2_buf,"Loopback");
            break;
        case 1:
            sprintf(l2_buf, "%02X:%02X:%02X:%02X:%02X:%02X <- %02X:%02X:%02X:%02X:%02X:%02X", packet[0],
            packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
            break;
        default:
            strcpy(l2_buf, "Unable to convert");
    }
        printf("[%s.%06ld] | L2-frame type: %d | %s | Pakiet len: %u\n",time_buf, header->ts.tv_usec, l2class, l2_buf, header->len);
        if(counter++ == 9) break;
    }
    if(packet_code == 1){
        printf("Maximum packet ammount reached");
    } else if(packet_code == 0) {
        printf("Closed due to timeout");
    } else {
        printf("Error: %s", pcap_geterr(handle));
    }
    
    pcap_close(handle);
    curdev = NULL;
    pcap_freealldevs(alldevs);
    return 0;
}