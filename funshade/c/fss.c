#include "fss.h"

// ---------------------------- HELPER FUNCTIONS ---------------------------- //
void xor(const uint8_t *a, const uint8_t *b, uint8_t *res, size_t s_len){
    size_t i;
    for (i = 0; i < s_len; i++)
    {
        res[i] = a[i] ^ b[i];
    }
}
void bit_decomposition(R_t value, bool *bits_array){
    size_t i;
    for (i = 0; i < N_BITS; i++)
    {
        bits_array[i] = value & (1ULL<<(N_BITS-i-1));
    }
}
void xor_cond(const uint8_t *a, const uint8_t *b, uint8_t *res, size_t len, bool cond){
    if (cond)
    {
        xor(a, b, res, len);
    }   
    else
    {
        memcpy(res, a, len);
    }
}

// -------------------------------------------------------------------------- //
// --------------------------- RANDOMNESS SAMPLING -------------------------- //
// -------------------------------------------------------------------------- //
#ifdef USE_LIBSODIUM
void init_libsodium(){
    if (sodium_init() < 0) /* panic! the library couldn't be initialized, it is not safe to use */
        {
            printf("<Funshade Error>: libsodium init failed\n");
            exit(EXIT_FAILURE);
        }
}
#endif

void random_buffer_seeded(uint8_t buffer[], size_t buffer_len, const uint8_t seed[SEED_LEN]){
    if (buffer==NULL)
    {
        printf("<Funshade Error>: buffer must have allocated memory to initialize\n");
        exit(EXIT_FAILURE);
    }
    #ifdef USE_LIBSODIUM // Secure random number generation using libsodium
        init_libsodium();
        if (seed == NULL)   // If seed is not provided, use secure randomness
        {
            randombytes_buf(buffer, buffer_len);
        }
        else                // Use provided seed
        {
            randombytes_buf_deterministic(buffer, buffer_len, seed);
        }
    #else               // Use insecure random number generation
        if (seed == NULL)
        {
            srand((unsigned int)time(NULL));        // Initialize random seed
        }
        else
        {
            srand(*((unsigned int*)seed));        // Initialize seeded
        }
        size_t i;
        for (i = 0; i < buffer_len; i++){
            buffer[i] = rand() % 256;
        }
    #endif
}
void random_buffer(uint8_t buffer[], size_t buffer_len){
    random_buffer_seeded(buffer, buffer_len, NULL);
}

R_t random_dtype_seeded(const uint8_t seed[SEED_LEN]){
    R_t value = 0;
    #ifdef USE_LIBSODIUM // Secure random number generation using libsodium
        init_libsodium();
        if (seed == NULL)   // If seed is not provided, use secure randomness
        {
            randombytes_buf(&value, sizeof(R_t));
        }
        else                // Use provided seed
        {
            randombytes_buf_deterministic(&value, sizeof(R_t), seed);
        }
    #else               // Use insecure random number generation
        if (seed != NULL)   // If seed is not provided, use secure randomness
        {
            srand(*((unsigned int*)seed));        // Initialize seeded
        }
        else                // Use provided seed
        {
            srand((unsigned int)time(NULL));        // Initialize random seed
        }
        size_t i;
        for (i = 0; i < sizeof(R_t); i++){
            value = (R_t)rand();
        }
    #endif
    return value;
}
R_t random_dtype(){
    return random_dtype_seeded(NULL);
}

// -------------------------------------------------------------------------- //
// ----------------- DISTRIBUTED COMPARISON FUNCTION (DCF) ------------------ //
// -------------------------------------------------------------------------- //
void DCF_gen_seeded(R_t alpha, uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN], uint8_t s0[S_LEN], uint8_t s1[S_LEN]){
    // Inputs and outputs to G
    uint8_t s0_i[S_LEN],  g_out_0[G_OUT_LEN],
            s1_i[S_LEN],  g_out_1[G_OUT_LEN];
    // Pointers to the various parts of the output of G
    uint8_t *s0_keep, *s0_lose, *v0_keep, *v0_lose, *t0_keep,
            *s1_keep, *s1_lose, *v1_keep, *v1_lose, *t1_keep;
    // Temporary variables
    uint8_t s_cw[S_LEN] = {0};
    R_t V_cw, V_alpha=0;    bool t0=0, t1=1;                                    // L3
    bool t_cw_L, t_cw_R, t0_L, t0_R, t1_L, t1_R;
    size_t i;

    // Decompose alpha into an array of bits                                    // L1
    bool alpha_bits[N_BITS] = {0};
    bit_decomposition(alpha, alpha_bits);

    // Initialize s0 and s1 randomly if they are NULL                           // L2
    if (s0==NULL || s1==NULL)
    {
        random_buffer(s0_i, S_LEN);
        random_buffer(s1_i, S_LEN);
    }
    else
    {
        memcpy(s0_i, s0, S_LEN);
        memcpy(s1_i, s1, S_LEN);
    }
    memcpy(&k0[S_PTR], s0_i, S_LEN);
    memcpy(&k1[S_PTR], s1_i, S_LEN);
    
    // Main loop
    for (i = 0; i < N_BITS; i++)                                         // L4
    {
        #ifdef __AES__
            G_ni(s0_i, g_out_0, G_IN_LEN, G_OUT_LEN);                           // L5
            G_ni(s1_i, g_out_1, G_IN_LEN, G_OUT_LEN);                           // L6
        #else
            G_tiny(s0_i, g_out_0, G_IN_LEN, G_OUT_LEN);                         // L5
            G_tiny(s1_i, g_out_1, G_IN_LEN, G_OUT_LEN);                         // L6
        #endif
        t0_L = TO_BOOL(g_out_0 + T_L_PTR);   t0_R = TO_BOOL(g_out_0 + T_R_PTR);
        t1_L = TO_BOOL(g_out_1 + T_L_PTR);   t1_R = TO_BOOL(g_out_1 + T_R_PTR);
        if (alpha_bits[i])  // keep = R; lose = L;                              // L8
        {
            s0_keep = g_out_0 + S_R_PTR;    s0_lose = g_out_0 + S_L_PTR;
            v0_keep = g_out_0 + V_R_PTR;    v0_lose = g_out_0 + V_L_PTR;
            t0_keep = g_out_0 + T_R_PTR;  //t0_lose = g_out_0 + T_L_PTR;
            s1_keep = g_out_1 + S_R_PTR;    s1_lose = g_out_1 + S_L_PTR;
            v1_keep = g_out_1 + V_R_PTR;    v1_lose = g_out_1 + V_L_PTR;
            t1_keep = g_out_1 + T_R_PTR;  //t1_lose = g_out_1 + T_L_PTR;
        }
        else                // keep = L; lose = R;                              // L7
        {
            s0_keep = g_out_0 + S_L_PTR;    s0_lose = g_out_0 + S_R_PTR;
            v0_keep = g_out_0 + V_L_PTR;    v0_lose = g_out_0 + V_R_PTR;
            t0_keep = g_out_0 + T_L_PTR;  //t0_lose = g_out_0 + T_R_PTR;
            s1_keep = g_out_1 + S_L_PTR;    s1_lose = g_out_1 + S_R_PTR;
            v1_keep = g_out_1 + V_L_PTR;    v1_lose = g_out_1 + V_R_PTR;
            t1_keep = g_out_1 + T_L_PTR;  //t1_lose = g_out_1 + T_R_PTR;
        }
        xor(s0_lose, s1_lose, s_cw, S_LEN);                                     // L10
        V_cw = (t1?-1:1) * (TO_R_t(v1_lose) - TO_R_t(v0_lose) - V_alpha);       // L11
        V_cw += alpha_bits[i] * (t1?-1:1) * BETA; // Lose=L --> alpha_bits[i]=1 // L12

        V_alpha += TO_R_t(v0_keep) - TO_R_t(v1_keep) + (t1?-1:1)*V_cw;          // L14
        t_cw_L = t0_L ^ t1_L ^ alpha_bits[i] ^ 1;                               // L15
        t_cw_R = t0_R ^ t1_R ^ alpha_bits[i];

        memcpy(&k0[CW_CHAIN_PTR + S_CW_PTR(i)], s_cw, S_LEN);                   // L16
        memcpy(&k0[CW_CHAIN_PTR + V_CW_PTR(i)], &V_cw, V_LEN);
        memcpy(&k0[CW_CHAIN_PTR + T_CW_L_PTR(i)], &t_cw_L, sizeof(bool));
        memcpy(&k0[CW_CHAIN_PTR + T_CW_R_PTR(i)], &t_cw_R, sizeof(bool));
        
        xor_cond(s0_keep, s_cw, s0_i, S_LEN, t0);                               // L18
        t0 = TO_BOOL(t0_keep) ^ (t0 & (alpha_bits[i]?t_cw_R:t_cw_L));           // L19
        xor_cond(s1_keep, s_cw, s1_i, S_LEN, t1);                                    
        t1 = TO_BOOL(t1_keep) ^ (t1 & (alpha_bits[i]?t_cw_R:t_cw_L));              
    }
    V_alpha = (t1?-1:1) * (TO_R_t(s1_i) - TO_R_t(s0_i) - V_alpha);              // L20
    memcpy(&k0[CW_CHAIN_PTR]+LAST_CW_PTR, &V_alpha,  sizeof(R_t));
    // Copy the resulting CW_chain                                              // L21
    memcpy(&k1[CW_CHAIN_PTR], &k0[CW_CHAIN_PTR], CW_CHAIN_LEN);
}
void DCF_gen(R_t alpha, uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN]){
    DCF_gen_seeded(alpha, k0, k1, NULL, NULL);
}

R_t DCF_eval(bool b, const uint8_t kb[KEY_LEN], R_t x_hat){
    R_t V = 0;     bool t = b, x_bits[N_BITS];                                  // L1
    uint8_t s[S_LEN], g_out[G_OUT_LEN];     
    size_t i;
    // Copy the initial state to avoid modifying the original key
    memcpy(s, &kb[S_PTR], S_LEN);
    // Decompose x into an array of bits
    bit_decomposition(x_hat, x_bits);

    // Main loop
    for (i = 0; i < N_BITS; i++)                                         // L2
    {
        #ifdef __AES__
            G_ni(s, g_out, G_IN_LEN, G_OUT_LEN);                                // L4
        #else
            G_tiny(s, g_out, G_IN_LEN, G_OUT_LEN);
        #endif
        if (x_bits[i]==0)  // Pick the Left branch
        {
           V += (b?-1:1) * (  TO_R_t(&g_out[V_L_PTR]) +                         // L7
                            t*TO_R_t(&kb[CW_CHAIN_PTR+V_CW_PTR(i)]));
           xor_cond(g_out+S_L_PTR, &kb[CW_CHAIN_PTR+S_CW_PTR(i)], s, S_LEN, t); // L8
           t = TO_BOOL(g_out+T_L_PTR) ^ (t&TO_BOOL(&kb[CW_CHAIN_PTR+T_CW_L_PTR(i)]));
        }
        else               // Pick the Right branch
        {
           V += (b?-1:1) * (  TO_R_t(&g_out[V_R_PTR]) +                         // L9
                            t*TO_R_t(&kb[CW_CHAIN_PTR+V_CW_PTR(i)]));
           xor_cond(g_out + S_R_PTR, &kb[CW_CHAIN_PTR+S_CW_PTR(i)], s, S_LEN, t);// L10  
           t = TO_BOOL(g_out+T_R_PTR) ^ (t&TO_BOOL(&kb[CW_CHAIN_PTR+T_CW_R_PTR(i)]));                    
        }
    }
    V += (b?-1:1) * (TO_R_t(s) + t*TO_R_t(&kb[CW_CHAIN_PTR+LAST_CW_PTR]));      // L13
    return V;
}

// -------------------------------------------------------------------------- //
// ------------------------- INTERVAL CONTAINMENT --------------------------- //
// -------------------------------------------------------------------------- //
void IC_gen(R_t r_in, R_t r_out, R_t p, R_t q, uint8_t k0_ic[KEY_LEN], uint8_t k1_ic[KEY_LEN]){
    DCF_gen((r_in-1), k0_ic, k1_ic);
    TO_R_t(&k0_ic[Z_PTR]) = random_dtype();
    TO_R_t(&k1_ic[Z_PTR]) = - TO_R_t(&k0_ic[Z_PTR]) + r_out 
                                + (U(p+r_in)  > U(q+r_in))  // alpha_p > alpha_q
                                - (U(p+r_in)  > U(p))       // alpha_p > p
                                + (U(q+r_in+1)> U(q+1))     // alpha_q_prime > q_prime
                                + (U(q+r_in+1)==U(0));      // alpha_q_prime = -1
}

R_t IC_eval(bool b, R_t p, R_t q, const uint8_t kb_ic[KEY_LEN], R_t x_hat){
    R_t output_1 = DCF_eval(b, kb_ic, (x_hat-p-1));
    R_t output_2 = DCF_eval(b, kb_ic, (x_hat-q-2));
    R_t output = b*((U(x_hat)>U(p))-(U(x_hat)>U(q+1))) - output_1 + output_2 + TO_R_t(&kb_ic[Z_PTR]);
    return output;
}


// -------------------------------------------------------------------------- //
// --------------------------------- SIGN ----------------------------------- //
// -------------------------------------------------------------------------- //
void SIGN_gen(R_t r_in, R_t r_out, uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN]){
    IC_gen(r_in, r_out, 0, (R_t)((1ULL<<(N_BITS-1))-1), k0, k1);
}
void SIGN_gen_batch(size_t K, R_t theta, R_t r_in_0[], R_t r_in_1[], uint8_t k0[], uint8_t k1[]){
    size_t k;

    // Generate masks
    random_buffer((uint8_t*)r_in_0, K*sizeof(R_t));
    random_buffer((uint8_t*)r_in_1, K*sizeof(R_t));
    for (k=0; k<K; k++)
    {
        SIGN_gen(r_in_0[k]+r_in_1[k], 0, &k0[k*KEY_LEN], &k1[k*KEY_LEN]);
        r_in_1[k] -= theta;
    }
}
R_t SIGN_eval(bool b, const uint8_t kb[KEY_LEN], R_t x_hat){
    return IC_eval(b, 0, (R_t)((1ULL<<(N_BITS-1))-1), kb, x_hat);
}
void SIGN_eval_batch(size_t K, bool b, const uint8_t kb[], const R_t x_hat[], R_t ob[]){
    size_t k;
    for (k=0; k<K; k++)
    {
        ob[k] = SIGN_eval(b, &kb[k*KEY_LEN], x_hat[k]);
    }
}


// -------------------------------------------------------------------------- //
// ------------------------------- FUNSHADE --------------------------------- //
// -------------------------------------------------------------------------- //

// .......................... Single evaluation ............................. //
void funshade_setup(size_t l, R_t theta, R_t r_in[2], R_t d_x0[], R_t d_x1[],
    R_t d_y0[], R_t d_y1[], R_t d_xy0[], R_t d_xy1[], uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN])
{
    size_t i;
    // Generate randomness for scalar product
    random_buffer((uint8_t*)d_x0, l*sizeof(R_t)); random_buffer((uint8_t*)d_x1, l*sizeof(R_t));
    random_buffer((uint8_t*)d_y0, l*sizeof(R_t)); random_buffer((uint8_t*)d_y1, l*sizeof(R_t));
    random_buffer((uint8_t*)d_xy0, l*sizeof(R_t));random_buffer((uint8_t*)r_in, 2*sizeof(R_t));
    for (i=0; i<l; i++)
    {
        d_xy1[i] = (d_x0[i]+d_x1[i]) * (d_y0[i]+d_y1[i]) - d_xy0[i];
    }
    // Generate keys
    SIGN_gen(r_in[0]+r_in[1], 0, k0, k1);
    // Remove threshold from r
    r_in[1] -= theta;
}


void funshade_share(size_t l, const R_t v[], const R_t d_v[], R_t D_v[])
{
    size_t i;
    for (i=0; i<l; i++)
    {
        D_v[i] = d_v[i] + v[i];
    }
}


R_t funshade_eval_dist(size_t l, bool j, R_t r_in_j,
    const R_t D_x[], const R_t D_y[], const R_t d_xj[], const R_t d_yj[], const R_t d_xyj[])
{
    size_t i;
    R_t z_hat_j = r_in_j;
    for (i=0; i<l; i++)
    {
        z_hat_j += j*(D_x[i]*D_y[i]) - (D_x[i]*d_yj[i]) - (D_y[i]*d_xj[i]) + d_xyj[i];
    }
    return z_hat_j;
}

R_t funshade_eval_sign(bool j, const uint8_t kb[KEY_LEN], R_t z_hat)
{
    return SIGN_eval(j, kb, z_hat);
}

// ........................... Batch evaluation ............................. //
void funshade_setup_batch(size_t K, size_t l, R_t theta,
    R_t d_x0[], R_t d_x1[], R_t d_y0[], R_t d_y1[], R_t d_xy0[],R_t d_xy1[],
    R_t r_in_0[],R_t r_in_1[], uint8_t k0[], uint8_t k1[])
{
    size_t idx, k;
    // Generate randomness for scalar product
    random_buffer((uint8_t*)d_x0, K*l*sizeof(R_t)); random_buffer((uint8_t*)d_x1, K*l*sizeof(R_t));
    random_buffer((uint8_t*)d_y0, K*l*sizeof(R_t)); random_buffer((uint8_t*)d_y1, K*l*sizeof(R_t));
    random_buffer((uint8_t*)d_xy0, K*l*sizeof(R_t));
#if defined(_OPENMP)
    #pragma omp parallel for
#endif
    for (idx=0; idx<(K*l); idx++)
    {
        d_xy1[idx] = (d_x0[idx]+d_x1[idx]) * (d_y0[idx]+d_y1[idx]) - d_xy0[idx];
    }
    // Generate masks and fss keys
    random_buffer((uint8_t*)r_in_0, K*sizeof(R_t));
    random_buffer((uint8_t*)r_in_1, K*sizeof(R_t));
#if defined(_OPENMP)
    #pragma omp parallel for
#endif
    for (k=0; k<K; k+=1)
    {
        SIGN_gen(r_in_0[k]+r_in_1[k], 0, &k0[k*KEY_LEN], &k1[k*KEY_LEN]);
        // Remove threshold from r_in shares
        r_in_1[k] -= theta;
    }
}

void funshade_share_batch(size_t K, size_t l, const R_t v[], const R_t d_v[],
    R_t D_v[])
{
    size_t idx;

#if defined(_OPENMP)
    #pragma omp parallel for
#endif
    for (idx=0; idx<K*l; idx++)
    {
        D_v[idx] = d_v[idx] + v[idx];
    }
}

void funshade_eval_dist_batch(size_t K, size_t l, bool j, const R_t r_in_j[], 
    const R_t D_x[], const R_t D_y[], const R_t d_xj[], const R_t d_yj[],
    const R_t d_xyj[], R_t z_hat_j[])
{
    size_t k,i,idx;
    memcpy(z_hat_j, r_in_j, K*sizeof(R_t));
#if defined(_OPENMP)
    #pragma omp parallel for
#endif
    for (k=0; k<K; k++)
    {
        for (i=0; i<l; i++)
        {
            idx = k*l + i;
            z_hat_j[k] += j*(D_x[idx]*D_y[idx]) - (D_x[idx]*d_yj[idx]) - (D_y[idx]*d_xj[idx]) + d_xyj[idx];
        }
    }
}

void funshade_eval_sign_batch(size_t K, bool j, const uint8_t k_j[], const R_t z_hat_0[], const R_t z_hat_1[], R_t o_j[])
{
    size_t k;
#if defined(_OPENMP)
    #pragma omp parallel for
#endif
    for (k=0; k<K; k++)
    {
        o_j[k]= SIGN_eval(j, &k_j[k*KEY_LEN], z_hat_0[k]+z_hat_1[k]);
    }
}

R_t funshade_eval_sign_batch_collapse(size_t K, bool j, const uint8_t k_j[], const R_t z_hat_0[], const R_t z_hat_1[])
{
    R_t o_j = 0;
    size_t k;
#if defined(_OPENMP)
    #pragma omp parallel for
#endif
    for (k=0; k<K; k++)
    {
        o_j += SIGN_eval(j, &k_j[k*KEY_LEN], z_hat_0[k]+z_hat_1[k]);
    }
    return o_j;
}