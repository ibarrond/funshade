#ifndef __FSS_H__
#define __FSS_H__

#include <stdint.h>     // uint8_t, uint32_t, uint64_t
#include <stdbool.h>    // bool, true, false
#include <stdio.h>      // printf()
#include <time.h>       // time()
#include <stdlib.h>     // rand(), srand()

//----------------------------------------------------------------------------//
// DEPENDENCIES
// #define USE_LIBSODIUM   // Use libsodium for secure random number generation
#ifdef USE_LIBSODIUM
#include "sodium.h"     // libsodium
#endif

#include "aes_ni.h" // AES-128-NI
// #include "aes_tiny.h"  // AES-128 standalone

//----------------------------------------------------------------------------//
//------------------------  CONFIGURABLE PARAMETERS --------------------------//
//----------------------------------------------------------------------------//
#define SEC_PARAM       128                 // Security parameter in bits

#define DTYPE_t         uint32_t            // Data type of the input to FSS gate
#define N_BITS          sizeof(DTYPE_t)*8   // Number of bits in DTYPE_t
#define BETA            1                   // Value of the output of the FSS gate

//----------------------------------------------------------------------------//
//-------------------------------- PRIVATE -----------------------------------//
//----------------------------------------------------------------------------//
// UTILS
#define CEIL(x,y)       (((x) - 1) / (y) + 1)               // x/y rounded up to the nearest integer
#define assertm(exp, msg) assert(((void)msg, exp))          // Assert with message
#define randombytes_SEEDBYTES 32                            // Seed size for randombytes_buf_deterministic()

// FIXED DEFINITIONS
#define G_IN_LEN        CEIL(SEC_PARAM,8)                   // [SEC_PARAM/8] input bytes
#define OUT_LEN         CEIL(2*SEC_PARAM+2*N_BITS+2,8)      // output bytes
#define G_OUT_LEN       (CEIL(OUT_LEN,G_IN_LEN)*G_IN_LEN)   // output bytes of G

#define TO_DTYPE(ptr)     (*((DTYPE_t*)(ptr)))              // Cast pointer to DTYPE_t
#define TO_BOOL(ptr)      ((bool)((*(uint8_t*)(ptr))&0x01)) // Cast pointer to bool

// Sizes of the various elements in the FSS key
#define S_LEN           G_IN_LEN                            // Size of the states s
#define V_LEN           sizeof(DTYPE_t)                     // Size of the masking values v
#define CW_LEN          (S_LEN + sizeof(DTYPE_t) + 2)       // Size of the correction words
#define CW_CHAIN_LEN    ((CW_LEN*N_BITS)+V_LEN)             // Size of the correction word chain

// Positions of the elements in key chain, for each correction word j
#define S_CW_PTR(j)     (j*CW_LEN)                          // Position of state s_cw
#define V_CW_PTR(j)     (S_CW_PTR(j) + S_LEN)               // Position of value v_cw
#define T_CW_L_PTR(j)   (V_CW_PTR(j) + V_LEN)               // Position of bit t_cw_l
#define T_CW_R_PTR(j)   (T_CW_L_PTR(j) + 1)                 // Position of bit t_cw_r
#define LAST_CW_PTR     (CW_LEN*N_BITS)                     // Position of last correction word, v_cw_n+1

// Positions of left and right elements in the output of G 
#define S_L_PTR         0                                   // Position of state s_l in G output
#define S_R_PTR         (S_L_PTR + S_LEN)                   // Position of state s_r in G output
#define V_L_PTR         (S_R_PTR + S_LEN)                   // Position of value v_l in G output
#define V_R_PTR         (V_L_PTR + V_LEN)                   // Position of value v_r in G output
#define T_L_PTR         (V_R_PTR + V_LEN)                   // Position of bit t_l in G output
#define T_R_PTR         (T_L_PTR + 1)                       // Position of bit t_r in G output


//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//
struct dcf_key{
    uint8_t s[S_LEN];
    uint8_t CW_chain[CW_CHAIN_LEN];
};

struct ic_key{
    struct dcf_key dcf_k;
    DTYPE_t z;
};

//.............................. RANDOMNESS GEN ..............................//
DTYPE_t init_dtype_random();
DTYPE_t init_dtype_random_seeded(const uint8_t seed[randombytes_SEEDBYTES]);
void init_states_random(uint8_t sa[S_LEN], uint8_t sb[S_LEN]);
void init_states_random_seeded(uint8_t sa[S_LEN], uint8_t sb[S_LEN], const uint8_t seed[randombytes_SEEDBYTES]);

//................................ DCF GATE ..................................//

/// @brief Generate a FSS key pair for the Distributed Conditional Function (DCF) gate
/// @param alpha input mask (should be uniformly random in DTYPE_t)
/// @param k0   pointer to the key of party 0
/// @param k1   pointer to the key of party 1
/// @param s0   Initial seed/state of party 0 (if NULL/unspecified, will be generated)
/// @param s1   Initial seed/state of party 1 (if NULL/unspecified, will be generated)
void DCF_gen       (DTYPE_t alpha, struct dcf_key *k0, struct dcf_key *k1);
void DCF_gen_seeded(DTYPE_t alpha, struct dcf_key *k0, struct dcf_key *k1, uint8_t s0[S_LEN], uint8_t s1[S_LEN]);

/// @brief Evaluate the DCF gate for a given input x in a 2PC setting
/// @param b    party number (0 or 1)
/// @param kb   pointer to the key of the party
/// @param x    public input to the FSS gate
/// @return     result of the FSS gate o, such that o0 + o1 = BETA*(x>alpha)
DTYPE_t DCF_eval(bool b, struct dcf_key *kb, DTYPE_t x);


//................................ IC GATE ...................................//
void IC_gen(DTYPE_t r_in, DTYPE_t r_out, DTYPE_t p, DTYPE_t q, struct ic_key *k0_ic, struct ic_key *k1_ic);
DTYPE_t IC_eval(bool b, DTYPE_t p, DTYPE_t q, struct ic_key *kb_ic, DTYPE_t x);

#endif // __FSS_H__