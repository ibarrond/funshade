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
    #define SEED_LEN        randombytes_SEEDBYTES
#else
    #define SEED_LEN        32
#endif

#if defined(_OPENMP)
    #include <omp.h>        // OpenMP header
#endif

#include "aes.h" // AES-128-NI and AES-128-standalone

//----------------------------------------------------------------------------//
//------------------------  CONFIGURABLE PARAMETERS --------------------------//
//----------------------------------------------------------------------------//
#define SEC_PARAM       128                 // Security parameter in bits
#ifndef R_t
#define R_t             int32_t             // Ring data type for all the constructions
#endif
#define BETA            1                   // Value of the output of the FSS gate

//----------------------------------------------------------------------------//
//-------------------------------- PRIVATE -----------------------------------//
//----------------------------------------------------------------------------//
// UTILS
#define CEIL(x,y)       (((x) - 1) / (y) + 1)               // x/y rounded up to the nearest integer
#define assertm(exp, msg) assert(((void)msg, exp))          // Assert with message
#define U(x)            ((unsigned)(x))                     // Unsigned cast

// FIXED DEFINITIONS
#define N_BITS          sizeof(R_t)*8                       // Number of bits in R_t

#define G_IN_LEN        CEIL(SEC_PARAM,8)                   // [SEC_PARAM/8] input bytes
#define OUT_LEN         CEIL(2*SEC_PARAM+2*N_BITS+2,8)      // output bytes
#define G_OUT_LEN       (CEIL(OUT_LEN,G_IN_LEN)*G_IN_LEN)   // output bytes of G

#define TO_R_t(ptr)     (*((R_t*)(ptr)))                    // Cast pointer to R_t
#define TO_BOOL(ptr)    ((bool)((*(uint8_t*)(ptr))&0x01))   // Cast pointer to bool

// Sizes of the various elements in the FSS key
#define S_LEN           G_IN_LEN                            // Size of the states s
#define V_LEN           sizeof(R_t)                         // Size of the masking values V
#define CW_LEN          (S_LEN + sizeof(R_t) + 2)           // Size of the correction words
#define CW_CHAIN_LEN    ((CW_LEN*N_BITS)+V_LEN)             // Size of the correction word chain
#define KEY_LEN         (S_LEN + CW_CHAIN_LEN + V_LEN)      // Size of the FSS key

// Positions of the elements in the correction word chain, for each correction word j
#define S_CW_PTR(j)     (j*CW_LEN)                          // Position of state s_cw
#define V_CW_PTR(j)     (S_CW_PTR(j) + S_LEN)               // Position of value V_cw
#define T_CW_L_PTR(j)   (V_CW_PTR(j) + V_LEN)               // Position of bit t_cw_l
#define T_CW_R_PTR(j)   (T_CW_L_PTR(j) + 1)                 // Position of bit t_cw_r
#define LAST_CW_PTR     (CW_LEN*N_BITS)                     // Position of last correction word, V_cw_n+1

// Positions of left and right elements in the output of G 
#define S_L_PTR         0                                   // Position of state s_l in G output
#define S_R_PTR         (S_L_PTR + S_LEN)                   // Position of state s_r in G output
#define V_L_PTR         (S_R_PTR + S_LEN)                   // Position of value v_l in G output
#define V_R_PTR         (V_L_PTR + V_LEN)                   // Position of value v_r in G output
#define T_L_PTR         (V_R_PTR + V_LEN)                   // Position of bit t_l in G output
#define T_R_PTR         (T_L_PTR + 1)                       // Position of bit t_r in G output

// Positions of the elements in the FSS key
#define S_PTR           0                                   // Position of state s
#define CW_CHAIN_PTR    (S_PTR + S_LEN)                     // Position of correction word chain
#define Z_PTR           (CW_CHAIN_PTR + CW_CHAIN_LEN)       // Position of value z

//----------------------------------------------------------------------------//
//--------------------------------  PRIVATE  ---------------------------------//
//----------------------------------------------------------------------------//
void xor(const uint8_t *a, const uint8_t *b, uint8_t *res, size_t s_len);
void bit_decomposition(R_t value, bool *bits_array);
void xor_cond(const uint8_t *a, const uint8_t *b, uint8_t *res, size_t len, bool cond);
#ifdef USE_LIBSODIUM
void init_libsodium();
#endif
//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//

//.............................. RANDOMNESS GEN ..............................//
// Manages randomness. Uses libsodium (cryptographically secure) if USE_LIBSODIUM
//  is defined, otherwise uses rand() (not cryptographically secure but portable).
R_t random_dtype();                                    // Non-deterministic seed
R_t random_dtype_seeded(const uint8_t seed[SEED_LEN]);
void random_buffer(uint8_t buffer[], size_t buffer_len);   // Non-deterministic seed 
void random_buffer_seeded(uint8_t buffer[], size_t buffer_len, const uint8_t seed[SEED_LEN]);

//................................ DCF GATE ..................................//
// FSS gate for the Distributed Conditional Function (DCF) gate.
//  Yields o0 + o1 = BETA*((unsigned)x>(unsigned)alpha)

/// @brief Generate a FSS key pair for the DCF gate
/// @param alpha input mask (should be uniformly random in R_t)
/// @param k0   pointer to the key of party 0
/// @param k1   pointer to the key of party 1
/// @param s0   Initial seed/state of party 0 (if NULL/unspecified, will be generated)
/// @param s1   Initial seed/state of party 1 (if NULL/unspecified, will be generated)
void DCF_gen(R_t alpha, uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN]);
void DCF_gen_seeded(R_t alpha, uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN], uint8_t s0[S_LEN], uint8_t s1[S_LEN]);

/// @brief Evaluate the DCF gate for a given input x in a 2PC setting
/// @param b        party number (0 or 1)
/// @param kb       pointer to the key of the party
/// @param x_hat    public input to the FSS gate
/// @return         result of the FSS gate o, such that o0 + o1 = BETA*((unsigned)x>(unsigned)alpha)
R_t DCF_eval(bool b, const uint8_t kb[KEY_LEN], R_t x_hat);


//................................ IC GATE ...................................//

/// @brief Generate a FSS key pair for the Interval Containment (IC) gate.
/// @param r_in     input mask (should be uniformly random in R_t)
/// @param r_out    output mask (should be uniformly random in R_t)
/// @param p        lower bound of the interval
/// @param q        upper bound of the interval
/// @param k0_ic    pointer to the key of party 0
/// @param k1_ic    pointer to the key of party 1
void IC_gen(R_t r_in, R_t r_out, R_t p, R_t q, uint8_t k0_ic[KEY_LEN], uint8_t k1_ic[KEY_LEN]);

/// @brief Evaluate the IC gate for a given input x in a 2PC setting
/// @param b        party number (0 or 1)
/// @param p        lower bound of the interval
/// @param q        upper bound of the interval
/// @param kb_ic    pointer to the function key of the party
/// @param x_hat    public input to the FSS gate
/// @return         result of the FSS gate oj, such that o0 + o1 = BETA*(p<=x<=q)
R_t IC_eval(bool b, R_t p, R_t q, const uint8_t kb_ic[KEY_LEN], R_t x_hat);

//................................. SIGN GATE ................................//
void SIGN_gen(R_t r_in, R_t r_out, uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN]);
R_t SIGN_eval(bool b, const uint8_t kb[KEY_LEN], R_t x_hat);
void SIGN_gen_batch(size_t K, R_t theta, R_t r_in_0[], R_t r_in_1[], uint8_t k0[], uint8_t k1[]);
void SIGN_eval_batch(size_t K, bool b, const uint8_t kb[], const R_t x_hat[], R_t ob[]);

//................................. FUNSHADE .................................//
// SINGLE EVALUATION

/// @brief Setup for the Funshade protocol (protocol 3 in the paper)
/// @param[in] l            number of elements in the input vectors and shares
/// @param[in] theta        Comparison threshold
/// @param[out] r_in[l]     random mask containing the threshold
/// @param[out] d_x0[l]     delta share #0 of x
/// @param[out] d_x1[l]     delta share #1 of x
/// @param[out] d_y0[l]     delta share #0 of y
/// @param[out] d_y1[l]     delta share #1 of y
/// @param[out] d_xy0[l]    delta share #0 of <d_x*d_y>
/// @param[out] d_xy1[l]    delta share #1 of <d_x*d_y>
/// @param[out] k0[KEY_LEN] key #0 for fss sign gate 
/// @param[out] k1[KEY_LEN] key #1 for fss sign gate
void funshade_setup(size_t l, R_t theta, R_t r_in[2],
    R_t d_x0[], R_t d_x1[], R_t d_y0[], R_t d_y1[], R_t d_xy0[], R_t d_xy1[], uint8_t k0[KEY_LEN], uint8_t k1[KEY_LEN]);

/// @brief Share the input vector v, for v in {x, y} (protocol 4 in the paper)
/// @param[in] l        number of elements in the input vector and share
/// @param[in] v[l]     input vector
/// @param[in] d_v[l]   delta share of that input vector
/// @param[out] D_v[l]  Resulting Delta share of the input vector
void funshade_share(size_t l, const R_t v[], const R_t d_v[], R_t D_v[]);

/// @brief Local evaluation of distance metric (protocol 5 in the paper)
/// @param[in] l            number of elements in the input vectors
/// @param[in] j            party number (0 or 1)
/// @param[in] r_in_j       random mask containing the threshold
/// @param[in] D_x[l]       Delta share of x
/// @param[in] D_y[l]       Delta share of y
/// @param[in] d_xj[l]      delta share #j of x
/// @param[in] d_yj[l]      delta share #j of y
/// @param[in] d_xyj[l]     delta share #j of <d_x*d_y>
/// @return             Share #j of <f_dist(x,y)>
R_t funshade_eval_dist(size_t l, bool j, R_t r_in_j,
    const R_t D_x[], const R_t D_y[], const R_t d_xj[], const R_t d_yj[], const R_t d_xyj[]);

/// @brief Local evaluation of sign (protocol 6 in the paper)
/// @param j            party number (0 or 1)
/// @param kb[KEY_LEN]  key of the party
/// @param z_hat        Share #j of <f_dist(x,y)>
/// @return             Share #j of <f_dist(x,y)>=theta>    
R_t funshade_eval_sign(bool j, const uint8_t kb[KEY_LEN], R_t z_hat);


// BATCH EVALUATION
//  Same as above, but for a batch of K inputs. Could use OpenMP to parallelize.
void funshade_setup_batch(size_t K, size_t l, R_t theta,
    R_t d_x0[], R_t d_x1[], R_t d_y0[], R_t d_y1[], R_t d_xy0[],R_t d_xy1[],
    R_t r_in_0[],R_t r_in_1[], uint8_t k0[], uint8_t k1[]);

void funshade_share_batch(size_t K, size_t l, const R_t v[], const R_t d_v[],
    R_t D_v[]);

void funshade_eval_dist_batch(size_t K, size_t l, bool j,
    const R_t r_in_j[], const R_t D_x[], const R_t D_y[],
    const R_t d_xj[], const R_t d_yj[], const R_t d_xyj[],
    R_t z_hat_j[]);

void funshade_eval_sign_batch(size_t K, bool j, const uint8_t kj[], const R_t z_hat_0[], const R_t z_hat_1[], R_t o_j[]);
R_t funshade_eval_sign_batch_collapse(size_t K, bool j, const uint8_t kj[], const R_t z_hat_0[], const R_t z_hat_1[]);


#endif // __FSS_H__
