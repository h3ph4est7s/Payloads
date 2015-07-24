#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED
#define PREFIX s
#include <stdio.h>

struct commandcase                      //name to function iterate model
{
    char* string;                       //given command
    void (*func)(char*,int);            //matched function
    char* help;
};
extern FILE *fdopen (int __fd, __const char *__modes);
void PREFIX_ext(char *argv, int argc);
void PREFIX_ls(char *argv, int argc);
void PREFIX_arp(char *argv, int argc);
void PREFIX_kill(char *argv, int argc);
void PREFIX_help(char *argv, int argc);
void PREFIX_pivot(char *argv, int argc);
void* pivot_thread(void *pinput);
unsigned int cntargs(char *string);
void my_switch(char *string);
#endif // MAIN_H_INCLUDED
