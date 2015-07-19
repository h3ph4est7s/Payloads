#ifndef COMMANDS_H_INCLUDED
#define COMMANDS_H_INCLUDED
#define ARP_IP_SIZE 16
#define BUFFER_SIZE 256
#include <stdbool.h>
#include <netinet/in.h>

typedef struct ArpTag
{
    char ip_address[ARP_IP_SIZE]; 
    int hw_type;
    int flags;
    char mac_address[18];
    char mask[18];
    char device[10];
} ArpTag;

typedef struct ArpResult
{
    ArpTag* result;
    unsigned long counter;
} ArpResult;

struct String
{
    char *string;
    size_t length;
};
struct StringArray{
    struct String *strings;
    unsigned long count;
};
struct PivotInput{
    struct in_addr atk_ip;
    in_port_t atk_port;
    struct in_addr vktm_ip;
    in_port_t vktm_port;
};
extern struct StringArray * get_dir_list(char *argv,int argc);
extern ArpResult* get_arp(char *argv,int argc);
extern int free_str_array(struct StringArray *array);
extern void* pivot(void *pinput);
extern int kill_pivot();
#endif // COMMANDS_H_INCLUDED
