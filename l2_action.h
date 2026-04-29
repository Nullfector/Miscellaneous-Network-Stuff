#pragma once
#include <string.h>
#include <stdio.h>
#include <pcap.h>

#define HANDLE_SIZE 3

int32_t loopback_handle(char* buf, const u_char* packet){
    sprintf(buf,"Loopback | L3 code: %d",*(uint32_t*)packet);
    return *(uint32_t*)packet;
}
int32_t ether_handle(char* buf, const u_char* packet){
    sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X <- %02X:%02X:%02X:%02X:%02X:%02X | EtherType: %d", packet[0],
            packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7],packet[8],packet[9],packet[10],packet[11],
        packet[12]*256+packet[13]);
    return (uint32_t)(packet[12]*256+packet[13]);
}
int32_t def_handle(char* buf, const u_char* packet){
    strcpy(buf, "Unable to convert");
    return -1;
}

typedef int32_t (*HandlerPointer)(char*, const u_char*);

HandlerPointer VISUAL_HANDLE[HANDLE_SIZE] = {loopback_handle,ether_handle,def_handle};
