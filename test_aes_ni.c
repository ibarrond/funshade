
#define _POSIX_C_SOURCE 199309L // CLOCK_REALTIME

#include "aes_ni.h"
#include "aes_tiny.h"
#include <string.h> // memcmp
#include <stdio.h>  // printf
#include <time.h>   // clock_gettime


struct timespec start, end; // time-stamps

void tic(){
    clock_gettime(CLOCK_REALTIME, &start); // get initial time-stamp
}
void toc(char *msg){
    clock_gettime(CLOCK_REALTIME, &end);   // get final time-stamp
    double t_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
                (double)(end.tv_nsec - start.tv_nsec);
    printf("Time taken for %s: %f ns\n", msg, t_ns);
}

void print_array(char *name, uint8_t *array, size_t size){
    printf("%s = [", name);
    for (size_t i = 0; i < size; i++){
        printf("%02x, ", array[i]);
    }printf("]\n");
}

int main()
{
    uint8_t plain[16]      = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10};
    uint8_t hash_ni[48]    = {0};
    uint8_t hash_sa[48]    = {0};

    tic();
    G_ni(plain, hash_ni, sizeof(plain), sizeof(hash_ni));
    toc("G_ni");
    
    tic();
    G_sa(plain, hash_sa, sizeof(plain), sizeof(hash_sa));
    toc("G_sa");

    // Print both hashes
    print_array("hash_ni", hash_ni, sizeof(hash_ni));
    print_array("hash_sa", hash_sa, sizeof(hash_sa));

    // check if both hashes are equal with memcmp
    if (memcmp(hash_ni, hash_sa, sizeof(hash_ni)) == 0)
        printf("Hashes are equal. \n");
    else
        printf("Hashes are not equal. \n");


    return 0;
}