#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include <iphlpapi.h>

const char* prety_state(const PDWORD num_state){
    switch(*num_state){
        case MIB_TCP_STATE_CLOSED:
            return "Inactive";
        case MIB_TCP_STATE_LISTEN:
            return "Listening";
        case MIB_TCP_STATE_ESTAB:
            return "Established";
        case MIB_TCP_STATE_SYN_SENT:
            return "Waiting for SYN+ACK";
        case MIB_TCP_STATE_SYN_RCVD:
            return "Waiting for ACK";
        case MIB_TCP_STATE_DELETE_TCB:
            return "In deletion";
        default:
            return "Closing";
    }
}

int compare(const void* p1, const void* p2){
    return ((const MIB_TCPROW_OWNER_PID*)p1)->dwOwningPid - ((const MIB_TCPROW_OWNER_PID*)p2)->dwOwningPid;
}

int fun(){
    PMIB_TCPTABLE_OWNER_PID tcpTable;
    DWORD size; //to jest po prostu unsigned int - dlaczego utrudniacie mi rozumienie tego jaki typ jest jaki???

    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); //wyciąganie size-u aby stworzyć przechowalnie
    tcpTable = (PMIB_TCPTABLE_OWNER_PID) malloc(size);

    if(GetExtendedTcpTable(tcpTable, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) == NO_ERROR){
        
        qsort(tcpTable->table, tcpTable->dwNumEntries, sizeof(MIB_TCPROW_OWNER_PID),compare);
        printf("IPv4 sockets:\n=============================================================\n");
        DWORD lastPID = tcpTable->table[0].dwOwningPid;
        printf("+------ PID: %lu -------------------------------------------+\n", lastPID);

        for(DWORD i = 0; i< tcpTable->dwNumEntries;i++){
            struct in_addr localAddr, remoteAddr;
            localAddr.S_un.S_addr = tcpTable->table[i].dwLocalAddr;
            remoteAddr.S_un.S_addr = tcpTable->table[i].dwRemoteAddr;

            if(tcpTable->table[i].dwOwningPid != lastPID){
                printf("\n+------ PID: %lu -------------------------------------------+\n", tcpTable->table[i].dwOwningPid);
                lastPID = tcpTable->table[i].dwOwningPid;
            }
            printf("%s:%u -> %s:%u | State: %s\n",
                   inet_ntoa(localAddr),
                   ntohs((u_short)tcpTable->table[i].dwLocalPort),
                   inet_ntoa(remoteAddr),
                   ntohs((u_short)tcpTable->table[i].dwRemotePort),
                    prety_state(&(tcpTable->table[i].dwState)));
        }
    } else {
        printf("Error occured - quitting process.");
    }
    free(tcpTable);
}