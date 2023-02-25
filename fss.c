#include "fss.h"

// Initialize insecure randomness generation
static void init_insecure_rand(){srand((unsigned int)time(NULL));}

// Initialize libsodium for cryptographically secure randomness generation
static void init_secure_rand(){
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
        printf("<Funshade Error>: libsodium init failed in init_secure_rand\n");
        exit(1);}}

// sample alpha, s0 and s1 from uniform distributions
void init_states_n_mask(DTYPE_t alpha, uint8_t s0[S_LEN], uint8_t s1[S_LEN], size_t s_len){
    assert(s_len == S_LEN);

    if (s0==NULL || s1==NULL){
        printf("<Funshade Error>: s0|s1 are empty\n");
        exit(1);}
    
    #ifdef USE_LIBSODIUM // Initialize s0 and s1 to random values SECURELY if libsodium is available
    init_secure_rand();
    randombytes_buf(s0, S_LEN);
    randombytes_buf(s1, S_LEN);
    randombytes_buf(&alpha, sizeof(DTYPE_t));

    #else // Initialize s0 and s1 to random values INSECURELY otherwise
    init_insecure_rand();
    for (size_t i = 0; i < S_LEN; i++){
        s0[i] = rand() % 256;   s1[i] = rand() % 256;}
    for (size_t i = 0; i < sizeof(DTYPE_t); i++){
        *(uint8_t*)(&alpha+i) = rand() % 256;}
    #endif
}

static inline void xor(uint8_t *a, uint8_t *b, uint8_t *res, size_t s_len){
    for (size_t i = 0; i < s_len; i++){res[i] = a[i] ^ b[i];}}

static void print_state(uint8_t *s){
    printf("0x");
    for (size_t i = 0; i < (S_LEN/4); i++){
        printf("%02x", s[i]);
    }
}

void bit_decomposition(DTYPE_t alpha, bool *alpha_bits){
    for (size_t i = 0; i < N_BITS; i++){
        alpha_bits[i] = alpha & (1<<(N_BITS-i-1));
    }
}

void DCF_gen(DTYPE_t alpha, uint8_t s0[S_LEN], uint8_t s1[S_LEN], struct fss_key *k0, struct fss_key *k1){
    // Inputs and outputs to G
    uint8_t s0_i[S_LEN] = {0},  g_out_0[G_OUT_LEN]= {0},
            s1_i[S_LEN] = {0},  g_out_1[G_OUT_LEN]= {0};
    // Pointers to the various parts of the output of G
    uint8_t *s0_keep, *s0_lose, *v0_keep, *v0_lose, *t0_keep,
            *s1_keep, *s1_lose, *v1_keep, *v1_lose, *t1_keep;

    // Decompose alpha into an array of bits                                    // L1
    bool alpha_bits[N_BITS] = {0};
    bit_decomposition(alpha, alpha_bits);

    // Initialize s0 and s1 randomly if they are NULL                           // L2
    if (s0==NULL || s1==NULL){
        s0 = (uint8_t *) malloc(S_LEN);
        s1 = (uint8_t *) malloc(S_LEN);
        init_states_n_mask(alpha, s0, s1, S_LEN);
    }
    memcpy(s0_i, s0, S_LEN);
    memcpy(s1_i, s1, S_LEN);

    // Temporary variables
    uint8_t CW_chain[CW_CHAIN_LEN] = {0};
    uint8_t s_cw[S_LEN] = {0};
    DTYPE_t V_cw, V_alpha=0, V_check;    bool t0=0, t1=1;                                // L3
    bool t_cw_L, t_cw_R, t0_L, t0_R, t1_L, t1_R;


    // Main loop
    for (size_t i = 0; i < N_BITS; i++)                                         // L4
    {
        
        G_ni(s0_i, g_out_0, G_IN_LEN, G_OUT_LEN);                               // L5
        G_ni(s1_i, g_out_1, G_IN_LEN, G_OUT_LEN);                               // L6
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
        V_cw = (t1?-1:1) * (TO_DTYPE(v1_lose) - TO_DTYPE(v0_lose) - V_alpha);   // L11
        V_cw += alpha_bits[i] * (t1?-1:1) * BETA; // Lose=L --> alpha_bits[i]=1 // L12

        V_alpha += TO_DTYPE(v0_keep) - TO_DTYPE(v1_keep) + (t1?-1:1)*V_cw;      // L14
        t_cw_L = t0_L ^ t1_L ^ alpha_bits[i] ^ 1;                               // L15
        t_cw_R = t0_R ^ t1_R ^ alpha_bits[i];
        memcpy(CW_chain + S_CW_PTR(i), s_cw, S_LEN);                            // L16
        memcpy(CW_chain + V_CW_PTR(i), &V_cw, V_LEN);
        memcpy(CW_chain + T_CW_L_PTR(i), &t_cw_L, sizeof(bool));
        memcpy(CW_chain + T_CW_R_PTR(i), &t_cw_R, sizeof(bool));
        if (t0)
        {
            xor(s0_keep, s_cw, s0_i, S_LEN);                                    // L18
            t0 = TO_BOOL(t0_keep) ^ (alpha_bits[i]?t_cw_R:t_cw_L);              // L19
        }
        else
        {
            memcpy(s0_i, s0_keep, S_LEN);
            t0 = TO_BOOL(t0_keep);
        }
        if (t1)
        {
            xor(s1_keep, s_cw, s1_i, S_LEN);                                    
            t1 = TO_BOOL(t1_keep) ^ (alpha_bits[i]?t_cw_R:t_cw_L);              
        }
        else
        {
            memcpy(s1_i, s1_keep, S_LEN);
            t1 = TO_BOOL(t1_keep);
        }
        printf("(%u) alpha[i]:%u ", i, alpha_bits[i]);printf("s0: "); print_state(s0_i); printf("   s1: "); print_state(s1_i);
        printf("   t0:%d t1:%d", t0, t1);
        printf("  V_alpha:%-4u", V_alpha); printf("  V_cw:%-4u", V_cw); printf("  t_cw_L:%-4d t_cw_R:%-4d", t_cw_L, t_cw_R);
        // V_check =(1-2*alpha_bits[i]) * (TO_DTYPE(g_out_0 + V_R_PTR) - TO_DTYPE(g_out_0 + V_L_PTR) + 
        //                                 TO_DTYPE(g_out_1 + V_R_PTR) - TO_DTYPE(g_out_1 + V_L_PTR));
        // printf(" Check: %u", V_check);
        printf("  s_cw: "); print_state(s_cw); 
        printf("\n");


    }
    V_alpha = (t1?-1:1) * (TO_DTYPE(s1_i) - TO_DTYPE(s0_i) - V_alpha);          // L20
    printf("  Last V_alpha:%-4u\n", V_alpha);
    memcpy(CW_chain+LAST_CW_PTR, &V_alpha,  sizeof(DTYPE_t));

    // Prepare the resulting keys                                               // L21
    memcpy(k0->s, s0, S_LEN);
    memcpy(k1->s, s1, S_LEN);
    memcpy(k0->CW_chain, CW_chain, CW_CHAIN_LEN);
    memcpy(k1->CW_chain, CW_chain, CW_CHAIN_LEN);
    printf("setup Done\n");
}

void split_g_out(uint8_t g_out[G_OUT_LEN], uint8_t s_l[S_LEN], uint8_t s_r[S_LEN], uint8_t v_l[V_LEN], uint8_t v_r[V_LEN], bool *t_l, bool *t_r){
    memcpy(s_l, g_out + S_L_PTR, S_LEN);
    memcpy(s_r, g_out + S_R_PTR, S_LEN);
    memcpy(v_l, g_out + V_L_PTR, V_LEN);
    memcpy(v_r, g_out + V_R_PTR, V_LEN);
    *t_l = TO_BOOL(g_out + T_L_PTR);
    *t_r = TO_BOOL(g_out + T_R_PTR);
}

void xor_cond(uint8_t *a, uint8_t *b, uint8_t *res, size_t len, bool cond){
    if (cond)
        xor(a, b, res, len);
    else
        memcpy(res, a, len);
}

void DCF_gen_literal(DTYPE_t alpha, uint8_t s0[S_LEN], uint8_t s1[S_LEN], struct fss_key *k0, struct fss_key *k1){
    // Inputs and outputs to G
    uint8_t s0_i[S_LEN] = {0},  g_out_0[G_OUT_LEN]= {0},
            s1_i[S_LEN] = {0},  g_out_1[G_OUT_LEN]= {0};
    uint8_t s0_L[S_LEN] = {0}, s0_R[S_LEN] = {0},
            s1_L[S_LEN] = {0}, s1_R[S_LEN] = {0},
            v0_L[V_LEN] = {0}, v0_R[V_LEN] = {0},
            v1_L[V_LEN] = {0}, v1_R[V_LEN] = {0};
    bool t0_L, t0_R, t1_L, t1_R;
    uint8_t s0_keep[S_LEN] = {0}, s0_lose[S_LEN] = {0},
            s1_keep[S_LEN] = {0}, s1_lose[S_LEN] = {0},
            v0_keep[V_LEN] = {0}, v0_lose[V_LEN] = {0},
            v1_keep[V_LEN] = {0}, v1_lose[V_LEN] = {0};
    bool t0_keep, t0_lose, t1_keep, t1_lose, t_cw_keep;

    // Decompose alpha into an array of bits                                    // L1
    bool alpha_bits[N_BITS] = {0};
    bit_decomposition(alpha, alpha_bits);

    // Initialize s0 and s1 randomly if they are NULL                           // L2
    if (s0==NULL || s1==NULL){
        s0 = (uint8_t *) malloc(S_LEN);
        s1 = (uint8_t *) malloc(S_LEN);
        init_states_n_mask(alpha, s0, s1, S_LEN);
    }
    memcpy(s0_i, s0, S_LEN);
    memcpy(s1_i, s1, S_LEN);

    // Temporary variables
    uint8_t CW_chain[CW_CHAIN_LEN] = {0};
    uint8_t s_cw[S_LEN] = {0};
    DTYPE_t V_cw, V_alpha=0;    bool t0=0, t1=1;                       // L3
    bool t_cw_L, t_cw_R;
    DTYPE_t neg1_pow_t_i_neg1 = 0;


    // Main loop
    for (size_t i = 0; i < N_BITS; i++)                                         // L4
    {
        G_ni(s0_i, g_out_0, G_IN_LEN, G_OUT_LEN);                               // L5
        split_g_out(g_out_0, s0_L, s0_R, v0_L, v0_R, &t0_L, &t0_R);
        G_ni(s1_i, g_out_1, G_IN_LEN, G_OUT_LEN);                               // L6
        split_g_out(g_out_1, s1_L, s1_R, v1_L, v1_R, &t1_L, &t1_R);

        if (alpha_bits[i]==0)  // keep = L; lose = R;                           // L7
        {
            memcpy(s0_keep, s0_L, S_LEN);memcpy(s0_lose, s0_R, S_LEN);
            memcpy(v0_keep, v0_L, V_LEN);memcpy(v0_lose, v0_R, V_LEN);
            t0_keep = t0_L;t0_lose = t0_R;
            memcpy(s1_keep, s1_L, S_LEN);memcpy(s1_lose, s1_R, S_LEN);
            memcpy(v1_keep, v1_L, V_LEN);memcpy(v1_lose, v1_R, V_LEN);
            t1_keep = t1_L;t1_lose = t1_R;            
        }
        else                // keep = R; lose = L;                              // L8
        {
            memcpy(s0_keep, s0_R, S_LEN);memcpy(s0_lose, s0_L, S_LEN);
            memcpy(v0_keep, v0_R, V_LEN);memcpy(v0_lose, v0_L, V_LEN);
            t0_keep = t0_R;t0_lose = t0_L;
            memcpy(s1_keep, s1_R, S_LEN);memcpy(s1_lose, s1_L, S_LEN);
            memcpy(v1_keep, v1_R, V_LEN);memcpy(v1_lose, v1_L, V_LEN);
            t1_keep = t1_R;t1_lose = t1_L;
        }

        xor(s0_lose, s1_lose, s_cw, S_LEN);                                     // L10
        neg1_pow_t_i_neg1 = (t1?-1:1);
        V_cw = neg1_pow_t_i_neg1 * (TO_DTYPE(v1_lose) - TO_DTYPE(v0_lose) - V_alpha); // L11
        if (alpha_bits[i]==1){ // Lose=L --> alpha_bits[i]=1                    // L12
            V_cw +=  neg1_pow_t_i_neg1 * BETA;
        }

        V_alpha = V_alpha - TO_DTYPE(v1_keep) + TO_DTYPE(v0_keep) + neg1_pow_t_i_neg1*V_cw; // L14
        t_cw_L = t0_L ^ t1_L ^ alpha_bits[i] ^ 1;                               // L15
        t_cw_R = t0_R ^ t1_R ^ alpha_bits[i];
        t_cw_keep = (alpha_bits[i]?t_cw_R:t_cw_L);
        memcpy(CW_chain + S_CW_PTR(i), s_cw, S_LEN);                            // L16
        memcpy(CW_chain + V_CW_PTR(i), &V_cw, V_LEN);
        memcpy(CW_chain + T_CW_L_PTR(i), &t_cw_L, sizeof(bool));
        memcpy(CW_chain + T_CW_R_PTR(i), &t_cw_R, sizeof(bool));
        
        xor_cond(s0_keep, s_cw, s0_i, S_LEN, t0);                               // L17
        xor_cond(s1_keep, s_cw, s1_i, S_LEN, t1);
        t0 = t0_keep ^ (t0*t_cw_keep);                                          // L18
        t1 = t1_keep ^ (t1*t_cw_keep);

        // Print everything
        printf("(%u) alpha[i]:%u ", i, alpha_bits[i]);printf("s0: "); print_state(s0_i); printf("   s1: "); print_state(s1_i);
        printf("   t0:%d t1:%d", t0, t1);
        printf("  V_alpha:%-4u", V_alpha); printf("  V_cw:%-4u", V_cw); printf("  t_cw_L:%-4d t_cw_R:%-4d", t_cw_L, t_cw_R);
        printf("  s_cw: "); print_state(s_cw); 
        printf("\n");


    }
    V_alpha = (t1?-1:1) * (TO_DTYPE(s1_i) - TO_DTYPE(s0_i) - V_alpha);          // L20
     printf("  Last V_alpha:%-4u\n", V_alpha);
    memcpy(CW_chain+LAST_CW_PTR, &V_alpha,  sizeof(DTYPE_t));

    // Prepare the resulting keys                                               // L21
    memcpy(k0->s, s0, S_LEN);
    memcpy(k1->s, s1, S_LEN);
    memcpy(k0->CW_chain, CW_chain, CW_CHAIN_LEN);
    memcpy(k1->CW_chain, CW_chain, CW_CHAIN_LEN);
    printf("setup Done\n");
}


DTYPE_t DCF_eval(bool b, struct fss_key *kb, DTYPE_t x){
    DTYPE_t V = 0, V_cw;                                                              // L1
    bool t = b, t_cw_l, t_cw_r;
    uint8_t s[S_LEN]={0};               memcpy(s, kb->s, S_LEN);
    uint8_t s_cw[S_LEN]={0};
    uint8_t g_out[G_OUT_LEN]={0};
    uint8_t CW_chain[CW_CHAIN_LEN]={0}; memcpy(CW_chain, kb->CW_chain, CW_CHAIN_LEN);
    // uint8_t *s_hat_L, *s_hat_R, *v_hat_L, *v_hat_R, *t_hat_L, *t_hat_R;

    // Decompose x into an array of bits
    bool x_bits[N_BITS]={0};
    bit_decomposition(x, x_bits);

    // Main loop
    for (size_t i = 0; i < N_BITS; i++)                                         // L2
    {
        memcpy(s_cw, CW_chain + S_CW_PTR(i), S_LEN);                            // L3
        memcpy(&V_cw, CW_chain + V_CW_PTR(i), V_LEN);
        memcpy(&t_cw_l, CW_chain + T_CW_L_PTR(i), sizeof(bool));
        memcpy(&t_cw_r, CW_chain + T_CW_R_PTR(i), sizeof(bool));

        
        printf("s%-4d: ", b); print_state(s); printf("  V: %-4d  t: %-4d", V, t);
        printf("  s_cw: "); print_state(s_cw); printf("  V_cw: %-4d", V_cw);
        printf("  t_cw_l: %-4d  t_cw_r: %-4d", t_cw_l, t_cw_r);
        printf("\n");

        G_ni(s, g_out, G_IN_LEN, G_OUT_LEN);                                    // L4
        // s_hat_L = g_out + S_L_PTR;  s_hat_R = g_out + S_R_PTR;
        // v_hat_L = g_out + V_L_PTR;  v_hat_R = g_out + V_R_PTR;
        // t_hat_L = g_out + T_L_PTR;  t_hat_R = g_out + T_R_PTR;

        

        if (x_bits[i])  // Pick the Right branch
        {
            V += (b?-1:1) * (  TO_DTYPE(g_out + V_R_PTR) +                      // L9
                             t*TO_DTYPE(CW_chain + V_CW_PTR(i)) );
            if (t)                                                              // L10
            {
                xor(g_out + S_R_PTR, CW_chain + S_CW_PTR(i), s, S_LEN);
            }
            else
            {
                memcpy(s, g_out + S_R_PTR, S_LEN);
            }
            t = TO_BOOL(g_out + T_R_PTR) ^ (t & TO_BOOL(CW_chain + T_CW_R_PTR(i)));
        }
        else            // Pick the Left branch
        {
            V += (b?-1:1) * (  TO_DTYPE(g_out + V_L_PTR) +                      // L7
                             t*TO_DTYPE(CW_chain + V_CW_PTR(i)));
            if (t)                                                              // L8
            {
                xor(g_out + S_L_PTR, CW_chain + S_CW_PTR(i), s, S_LEN);
            }
            else
            {
                memcpy(s, g_out + S_L_PTR, S_LEN);
            }
            t = TO_BOOL(g_out + T_L_PTR) ^ (t & TO_BOOL(CW_chain + T_CW_L_PTR(i)));
            
        }
        
    }
    V += (b?-1:1) * (TO_DTYPE(s) + t*TO_DTYPE(CW_chain + LAST_CW_PTR));         // L13
    return V;
}


DTYPE_t DCF_eval_literal(bool b, struct fss_key *kb, DTYPE_t x){
    DTYPE_t V = 0, V_cw;                                                              // L1
    bool t = b, t_cw_l, t_cw_r;
    uint8_t s[S_LEN]={0};               memcpy(s, kb->s, S_LEN);
    uint8_t s_cw[S_LEN]={0};
    uint8_t g_out[G_OUT_LEN]={0};
    uint8_t CW_chain[CW_CHAIN_LEN]; memcpy(CW_chain, kb->CW_chain, CW_CHAIN_LEN);
    uint8_t s_hat_L[S_LEN]={0}, s_hat_R[S_LEN]={0}, v_hat_L[V_LEN]={0}, v_hat_R[V_LEN]={0};
    bool t_hat_L, t_hat_R;

    uint8_t s_L[S_LEN]={0}, s_R[S_LEN]={0};
    bool t_L, t_R;

    // Decompose x into an array of bits
    bool x_bits[N_BITS]={0};
    bit_decomposition(x, x_bits);

    // Main loop
    for (size_t i = 0; i < N_BITS; i++)                                         // L2
    {
        memcpy(s_cw, CW_chain + S_CW_PTR(i), S_LEN);                            // L3
        memcpy(&V_cw, CW_chain + V_CW_PTR(i), V_LEN);
        memcpy(&t_cw_l, CW_chain + T_CW_L_PTR(i), sizeof(bool));
        memcpy(&t_cw_r, CW_chain + T_CW_R_PTR(i), sizeof(bool));

        
        printf("s%-4d: ", b); print_state(s); printf("  V: %-4d  t: %-4d", V, t);
        printf("  s_cw: "); print_state(s_cw); printf("  V_cw: %-4d", V_cw);
        printf("  t_cw_l: %-4d  t_cw_r: %-4d", t_cw_l, t_cw_r);
        printf("\n");

        G_ni(s, g_out, G_IN_LEN, G_OUT_LEN);                                    // L4
        split_g_out(g_out, s_hat_L, s_hat_R, v_hat_L, v_hat_R, &t_hat_L, &t_hat_R);

        xor_cond(s_hat_L, s_cw, s_L, S_LEN, t);                                 // L5 & L6
        xor_cond(s_hat_R, s_cw, s_R, S_LEN, t);
        t_L = t_hat_L ^ (t & t_cw_l);
        t_R = t_hat_R ^ (t & t_cw_r);
        

        if (x_bits[i]==0)  // Pick the Left branch
        {
           V = V + (b?-1:1) * (TO_DTYPE(v_hat_L) + t*V_cw );          // L7
           memcpy(s, s_L, S_LEN);  t = t_L;                                     // L8    
        }
        else            // Pick the Right branch
        {
           V = V + (b?-1:1) * (TO_DTYPE(v_hat_R) + t*V_cw );          // L9
           memcpy(s, s_R, S_LEN);  t = t_R;                                     // L10
        }
        
    }
    V += (b?-1:1) * (TO_DTYPE(s) + t*TO_DTYPE(CW_chain + LAST_CW_PTR));         // L13
    return V;
}