#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <strings.h>
#include "commands.h"
#include "main.h"
#include "config.h"

int sockfd, newsockfd;

void PREFIX_ext(char *argv,int argc)
{
    close(newsockfd);
}

void PREFIX_arp(char *argv,int argc)
{
    ArpResult *resulthole = get_arp(NULL,1);
    ArpTag *out = resulthole->result;
    int cnt = resulthole->counter;
    ArpTag *outobj;
    FILE *fd = fdopen(newsockfd, "w");
    ssize_t f = write(newsockfd,"Address    HWtype    HWaddress     Flags Mask      Iface\n",57);
    if (f <= 0)
    {
        perror("ERROR writing to socket");
        return;
    }
    for(int counter = 0; counter < cnt; counter++)
    {
        outobj = &out[counter];
        int n = fprintf(fd, "%s    0x%x    %s     0x%x %s      %s\n",
                        outobj->ip_address,
                        outobj->hw_type,
                        outobj->mac_address,
                        outobj->flags,
                        outobj->mask,
                        outobj->device);
        if (n <= 0)
        {
            perror("ERROR writing to socket");
            return;
        }
        fflush(fd);
        free(resulthole->result);
        free(resulthole);
    }
}

int cntargs(char *string)               //space delimited arguments counter
{
    char* pch;                          //delimited token pointer
    char* buffin;                       //temporary buffer to slice pointer
    int count = 0;                      //arguments counter
    buffin = malloc(strlen(string)+1);  //allocate memory equal to length of string plus one
    if(buffin == NULL)                                     //if we cant allocate memory
    {
        perror("ERROR allocating memory");                 //print error message and
        exit(1);                                           //exit with status code 1
    }
    strcpy(buffin,string);                                 //copy contents of string limited by size of string to buffin
    pch = strtok(buffin," ");                              //slice the temporary buffer by space and then load the pointer of the first token to pch
    while (pch != NULL)                                    //iterate over pch until no more items
    {
        count++;                                           //increment arguments counter
        pch = strtok (NULL, " ");                          //set the pointer to the next element
    }
    free(buffin);                                          //free the temporary buffer
    return count;                                          //return the count result
}

void my_switch(char *string)
{

    struct commandcase cases [] =
    {
        { "exit", PREFIX_ext },
        { "arp", PREFIX_arp }
    };
    char *e;
    size_t index;
    char *command;
    bool allocated = false;
    e = strchr(string, ' ');
    if(e != NULL)
    {
        index = (size_t)(e - string);
        command = malloc(index+1);
        if(command == NULL)                                     //if we cant allocate memory
        {
            perror("ERROR allocating memory");                 //print error message and
            exit(1);                                           //exit with status code 1
        }
        command[index] = '\0';
        allocated = true;
        strncpy(command,string,index);
        e++;
    }
    else
    {
        e = string;
        command = string;
    }

    for(struct commandcase* pCase = cases; pCase != cases + sizeof( cases ) / sizeof( cases[0] ); pCase++ )
    {
        if( 0 == strcmp( pCase->string, command) )
        {
            (*pCase->func)(e,cntargs(e));
            break;
        }
    }
    if(allocated) free(command);

}

int main( int argc, char *argv[] )
{
    int clilen;
    uint16_t portno;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    ssize_t n;
    /* First call to socket() function */
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0)
    {
        perror("ERROR opening socket");
        exit(1);
    }

    /* Initialize socket structure */
    bzero((char *) &serv_addr, sizeof(serv_addr));
    portno = 5001;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    /* Now bind the host address using bind() call.*/
    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
    {
        perror("ERROR on binding");
        exit(1);
    }

    /* Now start listening for the clients, here process will
    * go in sleep mode and will wait for the incoming connection
    */

    listen(sockfd,5);
    clilen = sizeof(cli_addr);
    bzero(&buffer,256);
    char welcome[] = "Authentication: Success\n";
    while(true)
    {
        /* Accept actual connection from the client */
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, (socklen_t *)&clilen);
        if (newsockfd <= 0)
        {
            perror("ERROR on accept");
            continue;
        }
        bzero(&buffer,256);
        n = read( newsockfd,&buffer,255 );

        if (n <= 0)
        {
            perror("ERROR reading from socket");
            continue;
        }

        if(strcmp(strtok(buffer,"\n"),"lol") != 0)
        {
            perror("ERROR Auth failed.");
            close(newsockfd);
            continue;
        }
        n = write(newsockfd, welcome, strlen(welcome));

        if (n <= 0)
        {
            perror("ERROR writing to socket");
            continue;
        }
        FILE *fd = fdopen(newsockfd, "w");
        n = PRINT_VERSION(fd)
        fflush(fd);
        if (n <= 0)
        {
            perror("ERROR writing to socket");
            continue;
        }
        while(true)
        {
            bzero(&buffer,256);
            n = read( newsockfd,&buffer,255 );

            if (n <= 0)
            {
                perror("ERROR reading from socket");
                break;
            }
            strtok(buffer,"\n");
            if(strcmp(buffer,"\n") == 0)
            {
                continue;
            }
            my_switch(buffer);

        }
        close(newsockfd);
    }
}
