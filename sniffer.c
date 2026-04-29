#include <stdio.h>
#include <pcap.h>
#include <time.h>

#include "l2_action.h"

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

    char time_buf[64], l2_buf[64], l3_buf[64];
    int counter = 0;
    time_t sec;
    struct tm *tl;
    int l2class = pcap_datalink(handle), packet_code, l3class;
    while((packet_code = pcap_next_ex(handle, &header, &packet))==1){
        sec = header->ts.tv_sec;
        tl = localtime(&sec);
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tl);

        //z l2_action
        if(l2class<HANDLE_SIZE){
            l3class = VISUAL_HANDLE[l2class](l2_buf,packet);
        }
        else {
            l3class = VISUAL_HANDLE[HANDLE_SIZE-1](l2_buf,packet);
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