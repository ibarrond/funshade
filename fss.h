#ifndef __FSS_H__
#define __FSS_H__

#include <stdint.h>     // uint8_t, uint32_t, uint64_t
#include <stdbool.h>    // bool, true, false
#include <stdio.h>      // printf()
#include <time.h>       // time()
#include <stdlib.h>     // rand(), srand()

//----------------------------------------------------------------------------//
// DEPENDENCIES

#ifdef USE_LIBSODIUM
#include "sodium.h"     // libsodium
#endif

#include "aes_ni.h" // AES-128-NI
// #include "aes_tiny.h"  // AES-128 standalone

//----------------------------------------------------------------------------//
// CONFIGURABLE PARAMETERS
#define SEC_PARAM       128                 // Security parameter in bits

#define DTYPE_t         uint8_t             // Data type of the input to FSS gate
#define N_BITS          sizeof(DTYPE_t)*8   // Number of bits in DTYPE_t
#define BETA            1                   // Value of the output of the FSS gate

//----------------------------------------------------------------------------//
//-------------------------------- PRIVATE -----------------------------------//
//----------------------------------------------------------------------------//
// UTILS
#define CEIL(x,y)       (((x) - 1) / (y) + 1)// x/y rounded up to the nearest integer
#define assertm(exp, msg) assert(((void)msg, exp)) // Assert with message

// FIXED DEFINITIONS
#define G_IN_LEN        CEIL(SEC_PARAM,8)              // [SEC_PARAM/8] input bytes
#define OUT_LEN         CEIL(2*SEC_PARAM+2*N_BITS+2,8) // output bytes
#define G_OUT_LEN       (CEIL(OUT_LEN,G_IN_LEN)*G_IN_LEN)// output bytes of G

#define TO_DTYPE(ptr)     (*(DTYPE_t*)ptr)                     // Cast pointer ptr to DTYPE_t
#define TO_BOOL(ptr)      ((bool)((*(uint8_t*)(ptr))&0x01))    // Cast pointer ptr to bool

// Sizes of the various elements in the FSS key
#define S_LEN           G_IN_LEN
#define V_LEN           sizeof(DTYPE_t)
#define CW_LEN          (S_LEN + sizeof(DTYPE_t) + 2)
#define CW_CHAIN_LEN    ((CW_LEN*N_BITS)+V_LEN)

// Positions of left and right elements in the output of G 
#define S_L_PTR         0
#define S_R_PTR         (S_L_PTR + S_LEN)
#define V_L_PTR         (S_R_PTR + S_LEN)
#define V_R_PTR         (V_L_PTR + V_LEN)
#define T_L_PTR         (V_R_PTR + V_LEN)
#define T_R_PTR         (T_L_PTR + 1)

// Positions of the elements in key chain
#define S_CW_PTR(j)     (j*CW_LEN)
#define V_CW_PTR(j)     (S_CW_PTR(j) + S_LEN)
#define T_CW_L_PTR(j)   (V_CW_PTR(j) + V_LEN)
#define T_CW_R_PTR(j)   (T_CW_L_PTR(j) + 1)
#define LAST_CW_PTR     (CW_LEN*N_BITS)

struct fss_key{
    uint8_t s[S_LEN];
    uint8_t CW_chain[CW_CHAIN_LEN];
};


//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//

void bit_decomposition(DTYPE_t alpha, bool *alpha_bits);

// sample alpha, s0 and s1 from the uniform distribution over {0,1}^s_len
void init_states_n_mask(DTYPE_t alpha, uint8_t s0[S_LEN], uint8_t s1[S_LEN], size_t s_len);

// FSS key generation
//  - alpha: input uniformly random mask to the FSS gate
//  - s0, s1:    uniformly random initial states. Set to NULL to generate them.
//  - k0, k1:    pointers to the keys to be generated
void DCF_gen(DTYPE_t alpha, uint8_t s0[S_LEN], uint8_t s1[S_LEN], struct fss_key *k0, struct fss_key *k1);

//Second attempt.
void DCF_gen_literal(DTYPE_t alpha, uint8_t s0[S_LEN], uint8_t s1[S_LEN], struct fss_key *k0, struct fss_key *k1);

// FSS evaluation
//  - b:     party number (0 or 1)
//  - kb:    pointer to the key of the party (k0 or k1)
//  - x:     public (masked) input to the FSS gate. Should be hidden input + alpha
// > Return: result of the FSS gate ob, such that o0 + o1 = BETA
DTYPE_t DCF_eval(bool b, struct fss_key *kb, DTYPE_t x);

#endif // __FSS_H__