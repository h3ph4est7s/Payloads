#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "commands.h"




ArpResult* get_arp(char *argv,int argc)
{
    char line[500];                         // create a temporary line with 500 bytes limit
    struct ArpTag *out, *temp;              // declare two pointer variables which is defined by the arp tag structure
    static struct ArpResult result;         // declare a memory static variable which is defined by the arp result structure
    FILE *fp = fopen("/proc/net/arp", "r"); // get a file pointer to arp table pseudo file
    fgets(line, sizeof(line), fp);          // Skip the first line (column headers).
    out = malloc(sizeof(ArpTag));           // allocate memory equal to the size of the arp tag
    int count = 0;                          // declare the entries counter variable
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
