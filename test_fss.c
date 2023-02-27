
#define _POSIX_C_SOURCE 199309L // CLOCK_REALTIME
#define TIMEIT false // 1 to time the functions, 0 otherwise
#include <string.h> // memcmp
#include <stdio.h>  // printf
#include <time.h>   // clock_gettime

#include "fss.h"     // FSS functions

// ------------------------------ AUXILIARY --------------------------------- //
struct timespec start, end; // time-stamps
void tic(){
    if (TIMEIT)
        clock_gettime(CLOCK_REALTIME, &start); // get initial time-stamp
}
void toc(char *msg){
    if (TIMEIT){
        clock_gettime(CLOCK_REALTIME, &end);   // get final time-stamp
        double t_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
                    (double)(end.tv_nsec - start.tv_nsec);
        printf("Time taken for %s: %f ns\n", msg, t_ns);
    }
}


// ------------------------------ TESTS ------------------------------------- //
void test_dcf(int n_times) {
    // Inputs and outputs to FSS gate
    DTYPE_t alpha=0, // random mask
            x,       // masked input to DCF gate
            o0,      // output of FSS gate in party 0
            o1,      // output of FSS gate in party 1
            o;       // reconstructed output of DCF gate, should yield (x<alpha)

    // Allocate empty keys (k0, k1)
    struct dcf_key k0={0}, k1={0};
    
    // Generate a random mask alpha
    alpha = init_dtype_random();

    // Generate empty states (s0, s1). Alternatively, call DCF_gen() for automatic generation.
    uint8_t s0[S_LEN] = {0}, s1[S_LEN] = {0};
    init_states_random(s0, s1);

    // Generate keys once
    tic(); DCF_gen(alpha, &k0, &k1); toc("DCF_gen");
    
    // Test keys for multiple input values x
    for (int i=0; i<n_times; i++)
    {
        x = init_dtype_random();  // generate a random input x
        
        tic(); o0 = DCF_eval(0, &k0, x); toc("DCF_eval(0)");
        tic(); o1 = DCF_eval(1, &k1, x); toc("DCF_eval(1)");
        o = o0 + o1; 
        printf("x=%-10u | alpha=%-10u | o0=%-10u | o1=%-10u o0+o1=%-10u | "\
               "(x<alpha)=%-10u\n", x, alpha, o0, o1, o, (x<alpha));
    }
}

void test_ic(int n_times){
    // Inputs and outputs to FSS gate
    DTYPE_t alpha=0, // random mask
            x,       // masked input to DCF gate
            o0,      // output of FSS gate in party 0
            o1,      // output of FSS gate in party 1
            o;       // reconstructed output of DCF gate, should yield (x<alpha)

    // Allocate empty keys (k0, k1)
    struct ic_key k0={0}, k1={0};
    
    // Generate a random mask alpha
    alpha = init_dtype_random();

    // Generate keys once
    tic(); IC_gen(alpha, 0, 0, (1<<31), &k0, &k1); toc("IC_gen");
    
    // Test keys for multiple input values x
    for (int i=0; i<n_times; i++)
    {
        x = init_dtype_random();  // generate a random input x
        
        tic(); o0 = IC_eval(0,0, (1<<31), &k0, x); toc("IC_eval(0)");
        tic(); o1 = IC_eval(1, 0, (1<<31), &k1, x); toc("IC_eval(1)");
        o = o0 + o1; 
        printf("x=%-10u | alpha=%-10u | o0=%-10u | o1=%-10u o0+o1=%-10u | "\
               "(x<alpha)=%-10u\n", x, alpha, o0, o1, o, (x<alpha));
    }
}

// ------------------------------ MAIN -------------------------------------- //
int main() {
    // test_dcf(15);
    test_ic(15);
    exit(0);
}
