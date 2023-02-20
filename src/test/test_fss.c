#define USE_LIBSODIUM

#include <sodium.h>  // libsodium, for randombytes_buf
#include <stdio.h>   // printf

#include "fss.h"     // FSS functions



void test_fss(int n_times) {

    // Inputs and outputs to FSS gate
    DTYPE_t alpha, x, o0, o1;

    
    // Generate empty states (s0, s1), keys (k0, k1), and a random mask alpha
    uint8_t *s0=NULL, *s1=NULL;
    fss_key_t k0={0}, k1={0};
    randombytes_buf(&alpha, sizeof(DTYPE_t));


    // Generate keys once
    DCF_gen(alpha, s0, s1, S_LEN, &k0, &k1);

    // Test keys for multiple input values x
    for (int i=0; i<n_times; i++)
    {
        randombytes_buf(&x, sizeof(DTYPE_t));
        o0 = DCF_eval(0, &k0, x);
        o1 = DCF_eval(1, &k1, x);
        // o0+o1 should be equal to (x<alpha)
        printf("x=%d, alpha=%d, o0=%d, o1=%d, o0+o1=%d, (x<alpha)=%d\n", x, alpha, o0, o1, o0+o1, (x<alpha));
    }
}

void main() {
    test_fss(10);
    exit(0);
}
