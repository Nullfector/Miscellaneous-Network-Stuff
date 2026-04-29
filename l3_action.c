#include <pcap.h>
#include <stdio.h>

//2048 - ipv4, 34525 - ipv6, 2054 - arp, 34887 - MPLS, 34827 - PPP, 34984 - 802.1Q, 34958 - 802.1X, 36864 - loopback

#define L3_HANDLE_SIZE 8

int prettyIpv6(const u_char* ip){
    const u_char* end = NULL;
    const u_char* cur_val = ip, *prev_val = NULL;
    int max_len = 0, cur_len = 0;
    if(*cur_val+*(cur_val+1) == 0){
        cur_len = 1;
        end = cur_val;
    }
    for(int i=2;i<16;i+=2){ //pomijamy pierwszy wyraz
        prev_val = cur_val;
        cur_val = ip+i;
        if(*prev_val + *(prev_val+1)==0){
            //wcześniejsze było 0
            if(*cur_val + *(cur_val+1)==0){
                cur_len++;
            } else {
                if(cur_len > max_len){
                    max_len = cur_len;
                    end = cur_val;
                }
                cur_len = 0;
            }
        } else {
            //wcześniejsze nie było 0
            if(*cur_val + *(cur_val+1)==0){
                cur_len++;
            }
        }
    }
    int len_f = (end-2*max_len) - ip;
    return 100*len_f + 2*(max_len);
}

void printing(const u_char* ip, int control){
    for(int i=0;i<(control - control%100)/100;i+=2){
        printf("%X:",(uint16_t)*(ip+i) << 8 | *(ip+i+1));
    }
    for(int i=(control - control%100)/100 + control%100;i<16;i+=2){
        printf(":%X",(uint16_t)*(ip+i) << 8 | *(ip+i+1));
    }
}

int main(){
    u_char ip[16] = {0x20,0x01,0x0d,0xb8,0x0,0x0,0x0,0x0,0x0,0x0,0xff,0x0,0x0,0x34,0x56,0x78}; 
    int v = prettyIpv6(ip);
    printing(ip,v);
    return 0;
}

void ipv6Handler(char* buf, const u_char* packet){
    sprintf(buf,"Header len: %d | Next header: %d | ");
}

typedef void (*HandlerL3Pointer)(char*, const u_char*);