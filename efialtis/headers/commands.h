#ifndef COMMANDS_H_INCLUDED
#define COMMANDS_H_INCLUDED
#define ARP_IP_SIZE 16
#include <stdbool.h>

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
    bool freed;
};
struct StringArray{
    struct String *strings;
    unsigned long count;
    bool freed;
};
extern struct StringArray * get_dir_list(char *argv,int argc);
extern ArpResult* get_arp(char *argv,int argc);
extern int free_str_array(struct StringArray *array);

#endif // COMMANDS_H_INCLUDED
