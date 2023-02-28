//----------------------------------------------------------------------------//
// DEPENDENCIES
#define _POSIX_C_SOURCE 199309L // CLOCK_REALTIME
#include <string.h> // memcmp
#include <stdio.h>  // printf
#include <time.h>   // clock_gettime

#include "fss.h"     // FSS functions
#include "aes.h"     // AES-128-NI and AES-128-tiny (standalone)

//----------------------------------------------------------------------------//
//------------------------  CONFIGURABLE PARAMETERS --------------------------//
//----------------------------------------------------------------------------//
#define TIMEIT  1 // set to 1 to time the functions
#define PRINTIT 0 // set to 1 to print additional info
#define N_REPETITIONS 1000


//----------------------------------------------------------------------------//
// ------------------------------ AUXILIARY --------------------------------- //
//----------------------------------------------------------------------------//
struct timespec start, end; // time-stamps

void tic(){
    if(TIMEIT){
        clock_gettime(CLOCK_REALTIME, &start); // get initial time-stamp
    }
}
double toc(char *msg){
    if (TIMEIT){
        clock_gettime(CLOCK_REALTIME, &end);   // get final time-stamp
        double t_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
                    (double)(end.tv_nsec - start.tv_nsec);
        if (PRINTIT){
            printf("Time taken for %s: %.0f ns\n", msg, t_ns);
        }
        return t_ns;
    }
    return 0;
}
void print_buffer(const uint8_t *buffer, size_t size){
    printf("0x");
    for (size_t i = 0; i < size; i++){
        printf("%02x, ", buffer[i]);
    }
}

//----------------------------------------------------------------------------//
// ------------------------------ TESTS ------------------------------------- //
//----------------------------------------------------------------------------//
bool test_aes(int n_times) {
    uint8_t plain[G_IN_LEN]={0}, hash_ni[G_OUT_LEN]={0}, hash_sa[G_OUT_LEN]={0};
    double t_ni=0, t_sa=0;
    bool correct = true;

    for(int i=0; i<n_times; i++){
        // Generate random input
        random_buffer(plain, G_IN_LEN);

        // Hash input with both implementations
        tic();  G_ni  (plain, hash_ni, G_IN_LEN, G_OUT_LEN); t_ni+= toc("G_ni");
        tic();  G_tiny(plain, hash_sa, G_IN_LEN, G_OUT_LEN); t_sa+= toc("G_tiny");

        // Print both hashes
        #if PRINTIT
        print_buffer("hash_ni", hash_ni, sizeof(hash_ni));
        print_buffer("hash_sa", hash_sa, sizeof(hash_sa));
        #endif

        // check if both hashes are equal with memcmp
        correct &= (memcmp(hash_ni, hash_sa, sizeof(hash_ni)) == 0);
        #if PRINTIT
        if (correct){printf("Hashes are equal. \n");}
        else        {printf("Hashes are not equal. \n");}
        #endif
    }
    printf("Test AES fully correct: %s\n", correct ? "true" : "false");
    if (TIMEIT){
        printf(" - Avg. time G_ni:   %-5.0f (ns)\n", t_ni/n_times);
        printf(" - Avg. time G_tiny: %-5.0f (ns)\n", t_sa/n_times);
    }
    return correct;
}

bool test_dcf(int n_times) {
    double t_gen=0, t_eval=0;
    // Inputs and outputs to FSS gate
    DTYPE_t alpha=0, // random mask
            x,       // masked input to DCF gate
            o0,      // output of FSS gate in party 0
            o1,      // output of FSS gate in party 1
            o;       // reconstructed output of DCF gate, should yield (x<alpha)
    bool correct=true;

    // Allocate empty keys (k0, k1)
    struct dcf_key k0={0}, k1={0};
    
    // Generate a random mask alpha
    alpha = random_dtype();

    // Generate empty states (s0, s1). Alternatively, call DCF_gen() for automatic generation.
    uint8_t s0[S_LEN] = {0}, s1[S_LEN] = {0};
    random_buffer(s0, S_LEN);
    random_buffer(s1, S_LEN);

    // Generate keys once
    tic(); DCF_gen(alpha, &k0, &k1); t_gen += toc("DCF_gen");
    
    // Test keys for multiple input values x
    for (int i=0; i<n_times; i++)
    {
        x = random_dtype();  // generate a random input x
        
        tic(); o0 = DCF_eval(0, &k0, x); t_eval+= toc("DCF_eval(0)");
        tic(); o1 = DCF_eval(1, &k1, x); t_eval+= toc("DCF_eval(1)");
        o = o0 + o1; 
        correct &= ((unsigned)x<(unsigned)alpha) == (bool)o;
        #if PRINTIT
        printf("x=%-10u | alpha=%-10u | o0=%-10u | o1=%-10u o0+o1=%-10u | "\
               "(x<alpha)=%-10u\n", x, alpha, o0, o1, o, (x<alpha));
        #endif
    }
    printf("Test DCF fully correct: %s\n", correct ? "true" : "false");
    if (TIMEIT){
        printf(" - Avg. time DCF_gen:   %-5.0f (ns)\n", t_gen);
        printf(" - Avg. time DCF_eval:  %-5.0f (ns)\n", t_eval/(n_times*2));
    }
    return correct;
}

bool test_ic(int n_times){
    double t_gen=0, t_eval=0;
    // Inputs and outputs to FSS gate
    DTYPE_t r_in=0,  // random mask
            x,       // input to DCF gate (needs masking --> x + r_in)
            o0,      // output of FSS gate in party 0
            o1,      // output of FSS gate in party 1
            o;       // reconstructed output of DCF gate, should yield (x<r_in)
    bool correct=true;

    // Allocate empty keys (k0, k1)
    struct ic_key k0={0}, k1={0};
    
    // Generate a random mask r_in
    r_in = random_dtype();

    // Generate keys once
    DTYPE_t p = (DTYPE_t)(1<<(N_BITS-1)), q = -1;
    tic(); IC_gen(r_in, 0, p, q, &k0, &k1); t_gen += toc("IC_gen");
    
    // Test keys for multiple input values x
    for (int i=0; i<n_times; i++)
    {
        x = random_dtype();  // generate a random input x
        
        tic(); o0 = IC_eval(0, p, q, &k0, x+r_in); t_eval+= toc("IC_eval(0)");
        tic(); o1 = IC_eval(1, p, q, &k1, x+r_in); t_eval+= toc("IC_eval(1)");
        o = o0 + o1; 
        correct &= ((p<=x)&(x<q)) == (bool)o;

        #if PRINTIT
        printf("x=%-12d | r_in=%-12d | o0+o1=%-5d | "\
               "(p<=x<q)=%-5d\n", x, r_in, o, ((p<=x)&(x<q)));
        #endif
    }
    printf("Test IC fully correct: %s\n", correct ? "true" : "false");
    if (TIMEIT){
        printf(" - Avg. time IC_gen:   %-5.0f (ns)\n", t_gen);
        printf(" - Avg. time IC_eval:  %-5.0f (ns)\n", t_eval/(n_times*2));
    }
    return correct;
}

// ------------------------------ MAIN -------------------------------------- //
int main() {
    bool correct=true;
    correct &= test_aes(N_REPETITIONS);
    correct &= test_dcf(N_REPETITIONS);
    correct &= test_ic(N_REPETITIONS);
    if (PRINTIT)
        if (!correct)
            printf("Test failed. \n");
    exit(0);
}
