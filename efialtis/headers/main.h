#ifndef MAIN_H_INCLUDED
#define MAIN_H_INCLUDED
#define PREFIX s
#include <stdio.h>

struct commandcase                      //name to function iterate model
{
    char* string;                       //given command
    void (*func)(char*,int);            //matched function
};
extern FILE *fdopen (int __fd, __const char *__modes);
#endif // MAIN_H_INCLUDED
