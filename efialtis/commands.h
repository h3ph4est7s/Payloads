#ifndef COMMANDS_H_INCLUDED
#define COMMANDS_H_INCLUDED
#define ARP_IP_SIZE 16

typedef struct ArpTag
{
    char ip_address[ARP_IP_SIZE]; // Obviously more space than necessary, just illustrating here.
    int hw_type;
    int flags;
    char mac_address[18];
    char mask[18];
    char device[10];
} ArpTag;

typedef struct ArpResult
{
    ArpTag* result;
    int counter;
} ArpResult;

ArpResult* get_arp(char *argv,int argc);

#endif // COMMANDS_H_INCLUDED
