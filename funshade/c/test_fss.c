
//----------------------------------------------------------------------------//
//------------------------  CONFIGURABLE PARAMETERS --------------------------//
//----------------------------------------------------------------------------//
#define TIMEIT  1           // set to 1 to time the functions
#define PRINTIT 0           // set to 1 to print additional info
#define N_REPETITIONS 10    // number of repetitions for each test
#define N_REF_DB 5000       // (K) number of embeddings in the reference database 
#define EMBEDDING_LEN 512   // (l) Typically in {128, 256, 512} for face recog.

//----------------------------------------------------------------------------//
// DEPENDENCIES
#define _POSIX_C_SOURCE 199309L // CLOCK_REALTIME
#include <string.h> // memcmp
#include <stdio.h>  // printf
#include <time.h>   // clock_gettime
#include "fss.h"     // FSS functions
#include "aes.h"     // AES-128-NI and AES-128-tiny (standalone)




//----------------------------------------------------------------------------//
// ------------------------------ AUXILIARY --------------------------------- //
//----------------------------------------------------------------------------//
struct timespec start, end; // time-stamps

void tic(){
    if(TIMEIT){
        clock_gettime(CLOCK_REALTIME, &start); // get initial time-stamp
    }
}
double toc(){
    if (TIMEIT){
        clock_gettime(CLOCK_REALTIME, &end);   // get final time-stamp
        double t_ns = (double)(end.tv_sec - start.tv_sec) * 1.0e9 +
                    (double)(end.tv_nsec - start.tv_nsec);
        return t_ns;
    }
    return 0;
}
void print_buffer(const uint8_t *buffer, size_t size){
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++){
        printf("%02x, ", buffer[i]);
    }
}

//----------------------------------------------------------------------------//
// ------------------------------ TESTS ------------------------------------- //
//----------------------------------------------------------------------------//
bool test_aes(int n_times) {
    uint8_t plain[G_IN_LEN]={0}, hash_ni[G_OUT_LEN]={0}, hash_sa[G_OUT_LEN]={0};
    double t_ni=0, t_sa=0;
    int i;
    bool correct = true;

    for(i=0; i<n_times; i++){
        // Generate random input
        random_buffer(plain, G_IN_LEN);

        // Hash input with both implementations
        tic();  G_ni  (plain, hash_ni, G_IN_LEN, G_OUT_LEN); t_ni+= toc();
        tic();  G_tiny(plain, hash_sa, G_IN_LEN, G_OUT_LEN); t_sa+= toc();

        // check if both hashes are equal with memcmp
        correct &= (memcmp(hash_ni, hash_sa, sizeof(hash_ni)) == 0);
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
    R_t alpha=0,     // random mask
            x,       // masked input to DCF gate
            o0,      // output of FSS gate in party 0
            o1,      // output of FSS gate in party 1
            o;       // reconstructed output of DCF gate, should yield (x<alpha)
    bool correct=true, res;
    int i;
    
    // Allocate empty keys (k0, k1)
    uint8_t k0[KEY_LEN]={0}, k1[KEY_LEN]={0};
    
    // Generate a random mask alpha
    alpha = random_dtype();

    // Generate states (s0, s1). Alternatively, call DCF_gen() for automatic generation.
    uint8_t s0[S_LEN] = {0}, s1[S_LEN] = {0};
    random_buffer(s0, S_LEN);
    random_buffer(s1, S_LEN);

    // Test keys for multiple input values x
    for (i=0; i<n_times; i++)
    {
        // Generate keys
        tic(); DCF_gen(alpha, k0, k1); t_gen += toc();

        // generate a random input x
        x = random_dtype();  
        
        // Evaluate DCF gate
        tic(); o0 = DCF_eval(0, k0, x); t_eval+= toc();
        tic(); o1 = DCF_eval(1, k1, x); t_eval+= toc();
        o = o0 + o1;

        // Check if output is correct
        res = ((unsigned)x<(unsigned)alpha) == (bool)o; correct &= res;
    }
    printf("Test DCF fully correct: %s\n", correct ? "true" : "false");
    if (TIMEIT){
        printf(" - Avg. time DCF_gen:   %-5.0f (ns)\n", t_gen/(n_times));
        printf(" - Avg. time DCF_eval:  %-5.0f (ns)\n", t_eval/(n_times*2));
    }
    return correct;
}

bool test_ic(int n_times){
    double t_gen=0, t_eval=0;
    // Inputs and outputs to FSS gate
    R_t r_in=0,      // random mask
            x,       // input to DCF gate (needs masking --> x + r_in)
            o0,      // output of FSS gate in party 0
            o1,      // output of FSS gate in party 1
            o;       // reconstructed output of DCF gate, should yield (x<r_in)
    bool correct=true, res;
    int i;

    // Allocate empty keys (k0, k1)
    uint8_t k0[KEY_LEN]={0}, k1[KEY_LEN]={0};
    
    // Set top and bottom values of the interval
    R_t p = 0, q = (R_t)((1ULL<<(N_BITS-1))-1);

    for (i=0; i<n_times; i++)
    {
        // Generate a random mask r_in and keys (k0, k1)
        r_in = random_dtype();
        tic(); IC_gen(r_in, 0, p, q, k0, k1); t_gen += toc();

        // generate a random input x
        x = random_dtype();
        
        // Evaluate IC gate
        tic(); o0 = IC_eval(0, p, q, k0, x+r_in); t_eval+= toc();
        tic(); o1 = IC_eval(1, p, q, k1, x+r_in); t_eval+= toc();
        o = o0 + o1; 

        // Check if the result is correct
        res = ((p<=x)&(x<=q)) == (bool)o;   correct &= res;
    }
    printf("Test IC fully correct: %s\n", correct ? "true" : "false");
    if (TIMEIT){ 
        printf(" - Avg. time IC_gen:   %-5.0f (ns)\n", t_gen/(n_times));
        printf(" - Avg. time IC_eval:  %-5.0f (ns)\n", t_eval/(n_times*2));
    }
    return correct;
}


bool test_funshade(size_t n_times, size_t l){
    // Allocate empty everything with malloc
    uint8_t *k0 = (uint8_t*)malloc(KEY_LEN*sizeof(uint8_t));
    uint8_t *k1 = (uint8_t*)malloc(KEY_LEN*sizeof(uint8_t));
    R_t *x = (R_t*)malloc(l*sizeof(R_t));       R_t *y = (R_t*)malloc(l*sizeof(R_t));
    R_t *d_x = (R_t*)malloc(l*sizeof(R_t));     R_t *d_y = (R_t*)malloc(l*sizeof(R_t));
    R_t *d_x0 = (R_t*)malloc(l*sizeof(R_t));    R_t *d_y0 = (R_t*)malloc(l*sizeof(R_t));
    R_t *d_x1 = (R_t*)malloc(l*sizeof(R_t));    R_t *d_y1 = (R_t*)malloc(l*sizeof(R_t));
    R_t *d_xy0 = (R_t*)malloc(l*sizeof(R_t));   R_t *d_xy1 = (R_t*)malloc(l*sizeof(R_t));
    R_t *D_x = (R_t*)malloc(l*sizeof(R_t));     R_t *D_y = (R_t*)malloc(l*sizeof(R_t));
    R_t *r_in = (R_t*)malloc(2*sizeof(R_t));

    double t_setup=0, t_share=0, t_eval_sp=0, t_eval_sign=0;
    R_t     z, z_hat_0, z_hat_1, z_hat, // input to SIGN gate (needs masking --> z + r_in)
            o0, o1, o,                  // output of SIGN gate, should yield (z>=theta)
            theta;                      // threshold
    bool correct=true, res;
    size_t i, idx; 

    for (i=0; i<n_times; i++)
    {
        // Generate random inputs
        z = 0;
        for (idx=0; idx<l; idx++){
            x[idx] = random_dtype()/(2*l);
            y[idx] = random_dtype()/(2*l);
            z += x[idx]*y[idx];
        }
        // Generate a random threshold
        theta = random_dtype()/8; // theta in [0, 2^N_BITS/8]

        // Generate correlated randomness, input mask and fss keys
        tic(); funshade_setup(l, theta, r_in, d_x0, d_x1, d_y0, d_y1, d_xy0, d_xy1, k0, k1); t_setup += toc();
        for (idx=0; idx<l; idx++){
            d_x[idx] = d_x0[idx] + d_x1[idx];
            d_y[idx] = d_y0[idx] + d_y1[idx];
        }

        // Share inputs
        tic();  funshade_share(l, x, d_x, D_x);  t_share += toc();
        tic();  funshade_share(l, y, d_y, D_y);  t_share += toc();
        
        // Evaluate scalar product
        tic(); z_hat_0 = funshade_eval_dist(l, 0, r_in[0], D_x, D_y, d_x0, d_y0, d_xy0); t_eval_sp+= toc();
        tic(); z_hat_1 = funshade_eval_dist(l, 1, r_in[1], D_x, D_y, d_x1, d_y1, d_xy1); t_eval_sp+= toc();
        z_hat = z_hat_0 + z_hat_1;
        
        tic(); o0 = funshade_eval_sign(0, k0, z_hat); t_eval_sign+= toc();
        tic(); o1 = funshade_eval_sign(1, k1, z_hat); t_eval_sign+= toc();
        o = (o0 + o1);

        // Check if the result is correct
        res = (z>=theta) == (bool)o;   correct &= res;
    }
    printf("Test Funshade single fully correct: %s\n", correct ? "true" : "false");
    if (TIMEIT){
        printf(" - Avg. time funshade_setup:   %-5.0f (ns)\n", t_setup/(n_times));
        printf(" - Avg. time funshade_share:   %-5.0f (ns)\n", t_share/(n_times*2));
        printf(" - Avg. time funshade_eval_dist:  %-5.0f (ns)\n", t_eval_sp/(n_times*2));
        printf(" - Avg. time funshade_eval_sign:  %-5.0f (ns)\n", t_eval_sign/(n_times*2));
        // printf("l, t_setup_mean, t_share_mean, t_eval_sp_mean, t_eval_sign_mean, N_BITS, K\n");
        // printf("%lu, %f, %f, %f, %f, %lu\n", l, t_setup/(n_times), t_share/(n_times*2), 
        //                             t_eval_sp/(n_times*2), t_eval_sign/(n_times*2), N_BITS);
    }
    // Free everything
    free(x); free(y); free(d_x); free(d_y); free(d_x0); free(d_x1); free(d_y0); free(d_y1);
    free(D_x); free(D_y); free(r_in); free(k0); free(k1); free(d_xy0); free(d_xy1); 
    return correct;
}

bool test_funshade_batch(size_t n_times, size_t l, size_t K){
    // Allocate empty everything
    size_t v_size = l*K;
    R_t *x     = (R_t*)malloc(v_size*sizeof(R_t)),   *y     = (R_t*)malloc(v_size*sizeof(R_t)),
        *d_x   = (R_t*)malloc(v_size*sizeof(R_t)),   *d_y   = (R_t*)malloc(v_size*sizeof(R_t)),
        *d_x0  = (R_t*)malloc(v_size*sizeof(R_t)),   *d_y0  = (R_t*)malloc(v_size*sizeof(R_t)),
        *d_x1  = (R_t*)malloc(v_size*sizeof(R_t)),   *d_y1  = (R_t*)malloc(v_size*sizeof(R_t)),
        *D_x   = (R_t*)malloc(v_size*sizeof(R_t)),   *D_y   = (R_t*)malloc(v_size*sizeof(R_t)),
        *d_xy0 = (R_t*)malloc(v_size*sizeof(R_t)),   *d_xy1 = (R_t*)malloc(v_size*sizeof(R_t)),
        *r_in_0= (R_t*)malloc(K*sizeof(R_t)),        *r_in_1= (R_t*)malloc(K*sizeof(R_t)),
        *z_hat_0 = (R_t*)malloc(K*sizeof(R_t)),      *z_hat_1 = (R_t*)malloc(K*sizeof(R_t));
    uint8_t *k0 = (uint8_t*)malloc(K*KEY_LEN), *k1 = (uint8_t*)malloc(K*KEY_LEN);

    double t_setup=0, t_share=0, t_eval_sp=0, t_eval_sign=0;
    R_t *z     = (R_t*)calloc(v_size, sizeof(R_t));
    R_t     o0, o1, o,                  // output of SIGN gate, should yield (z>=theta)
            theta;                      // threshold
    bool correct=true, res;
    size_t i, idx;
    
    for (i=0; i<n_times; i++)
    {
        // Generate random inputs
        // z = 0;
        for (idx=0; idx<l*K; idx++){
            x[idx] = random_dtype()/(2*l);
            y[idx] = random_dtype()/(2*l);
            z[idx/l] += x[i]*y[i];
        }
        // Generate a random threshold
        theta = random_dtype()/8; // theta in [0, 2^N_BITS/8]

        // Generate correlated randomness, input mask and fss keys
        tic(); funshade_setup_batch(K, l, theta, d_x0, d_x1, d_y0, d_y1, d_xy0, d_xy1, r_in_0, r_in_1, k0, k1); t_setup += toc();
        for (idx=0; idx<l*K; idx++){
            d_x[idx] = d_x0[idx] + d_x1[idx];
            d_y[idx] = d_y0[idx] + d_y1[idx];
        }

        // Share inputs
        tic();  funshade_share_batch(K, l, x, d_x, D_x);  t_share += toc();
        tic();  funshade_share_batch(K, l, y, d_y, D_y);  t_share += toc();
        
        // Evaluate scalar product
        tic(); funshade_eval_dist_batch(K, l,  0, r_in_0, D_x, D_y, d_x0, d_y0, d_xy0, z_hat_0); t_eval_sp+= toc();
        tic(); funshade_eval_dist_batch(K, l,  1, r_in_1, D_x, D_y, d_x1, d_y1, d_xy1, z_hat_1); t_eval_sp+= toc();
        
        tic(); o0 = funshade_eval_sign_batch_collapse(K, 0, k0, z_hat_0, z_hat_1); t_eval_sign+= toc();
        tic(); o1 = funshade_eval_sign_batch_collapse(K, 1, k1, z_hat_0, z_hat_1); t_eval_sign+= toc();
        o = (o0 + o1);

        // Check if the result is correct, print if not
        res = 0;
        for (idx=0; idx<K; idx++){
            res += (z[idx]>=theta);
        }
        correct &= (res == (bool)o);
    }
    printf("Test Funshade batched fully correct: %s\n", correct ? "true" : "false");
    if (TIMEIT){
        printf(" - Avg. time funshade_setup:   %-5.0f (ns)\n", t_setup/(n_times));
        printf(" - Avg. time funshade_share:   %-5.0f (ns)\n", t_share/(n_times*2));
        printf(" - Avg. time funshade_eval_dist:  %-5.0f (ns)\n", t_eval_sp/(n_times*2));
        printf(" - Avg. time funshade_eval_sign:  %-5.0f (ns)\n", t_eval_sign/(n_times*2));
        // printf("l, t_setup_mean, t_share_mean, t_eval_sp_mean, t_eval_sign_mean, N_BITS, K\n");
        // printf("%lu, %f, %f, %f, %f, %lu, %lu\n", 
        //         l, t_setup/(n_times), t_share/(n_times*2), 
        //                             t_eval_sp/(n_times*2), t_eval_sign/(n_times*2), N_BITS, K);
    }
    // Free everything
    free(x); free(d_x); free(D_x); free(d_x0); free(d_x1); 
    free(y); free(d_y); free(D_y); free(d_y0); free(d_y1);
    free(d_xy0); free(d_xy1); free(r_in_0); free(r_in_1); free(z_hat_0); free(z_hat_1); free(k0); free(k1);
    free(z);
    return correct;
}


// ------------------------------ MAIN -------------------------------------- //
int main() {
    bool correct=true;
    correct &= test_aes(N_REPETITIONS);
    correct &= test_dcf(N_REPETITIONS);
    correct &= test_ic(N_REPETITIONS);
    correct &= test_funshade(N_REPETITIONS, 1);
    correct &= test_funshade(N_REPETITIONS, EMBEDDING_LEN);
    correct &= test_funshade_batch(N_REPETITIONS, EMBEDDING_LEN, N_REF_DB);
    if (correct)
    {
        printf("All Tests passed. \n");
    } else {
        printf("Tests failed. \n");
    }        
    exit(0);
}
