
#define _POSIX_C_SOURCE 199309L // CLOCK_REALTIME

#include <string.h> // memcmp
#include <stdio.h>  // printf
#include <time.h>   // clock_gettime

#include "fss.h"     // FSS functions


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


void test_fss(int n_times) {

    // Inputs and outputs to FSS gate
    DTYPE_t alpha=0, x, o0, o1, o;

    // Generate empty states (s0, s1), keys (k0, k1), and a random mask alpha
    uint8_t *s0 = (uint8_t *) malloc(S_LEN);
    uint8_t *s1 = (uint8_t *) malloc(S_LEN);
    init_states_n_mask(alpha, s0, s1, S_LEN);

    struct fss_key k0={0}, k1={0};
    randombytes_buf(&alpha, sizeof(DTYPE_t));

    // Generate keys once
    DCF_gen(alpha, s0, s1, &k0, &k1);

    // Test keys for multiple input values x
    for (int i=0; i<n_times; i++)
    {
        // randombytes_buf(&x, sizeof(DTYPE_t));
        x = alpha;
        o0 = DCF_eval(0, &k0, x);
        o1 = DCF_eval(1, &k1, x);
        o = o0 + o1; // o0+o1 should be equal to (x<alpha)
        // o0+o1 should be equal to (x<alpha)
        printf("x=%-10u,\t alpha=%-10u,\t  o0=%-10u,\t  o1=%-10u,\t  o0+o1=%-10u,\t  (x<alpha)=%-10u\n", x, alpha, o0, o1, o, (x<alpha));
    }
}

int main() {
    test_fss(1);
    exit(0);
}
