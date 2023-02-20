#include <stdint.h>     // uint8_t, uint32_t, uint64_t
#include <stdbool.h>    // bool, true, false
#include <stdio.h>      // printf()
#include <time.h>       // time()
#include <stdlib.h>     // rand(), srand()

#include "aes/aes_ni.h" // AES-128-NI

//----------------------------------------------------------------------------//
// CONFIGURABLE PARAMETERS
#define SEC_PARAM       128                 // Security parameter in bits
#define AES_BLOCKLEN    16                  // AES block length in bytes

#define DTYPE_t         int32_t             // Data type of the input to FSS gate
#define N_BITS          sizeof(DTYPE_t)*8   // Number of bits in DTYPE_t
#define BETA            1                   // Value of the output of the FSS gate

//----------------------------------------------------------------------------//
// FIXED DEFINITIONS
#define CEIL(x,y)       (((x) - 1) / (y) + 1)// x/y rounded up to the nearest integer

#define G_IN_LEN        CEIL(SEC_PARAM,8)              // [SEC_PARAM/8] input bytes
#define G_OUT_LEN       CEIL(2*SEC_PARAM+2*N_BITS+2,8) // output bytes

#define TO_DTYPE(ptr)     (*(DTYPE_t*)ptr)             // Cast pointer ptr to DTYPE_t
#define TO_BOOL(ptr)      ((*(bool*)(ptr))&1)          // Cast pointer ptr to bool

// Sizes of the various elements in the FSS key
#define S_LEN           G_IN_LEN
#define V_LEN           sizeof(DTYPE_t)
#define CW_LEN          S_LEN + sizeof(DTYPE_t) + 2
#define CW_CHAIN_LEN    CW_LEN*(N_BITS)+V_LEN

// Positions of left and right elements in the output of G 
#define S_L_PTR         0
#define S_R_PTR         S_L_PTR + S_LEN
#define V_L_PTR         S_R_PTR + V_LEN
#define V_R_PTR         V_L_PTR + V_LEN
#define T_L_PTR         V_R_PTR + 1
#define T_R_PTR         T_L_PTR + 1

// Positions of the elements in key chain
#define S_CW_PTR(i)     i*CW_LEN
#define V_CW_PTR(i)     S_CW_PTR(i) + S_LEN
#define T_CW_L_PTR(i)   V_CW_PTR(i) + V_LEN
#define T_CW_R_PTR(i)   T_CW_L_PTR(i) + 1
#define LAST_CW_PTR     CW_LEN*(N_BITS)

struct fss_key
{
    uint8_t *s[S_LEN];
    uint8_t *CW_chain[CW_LEN*(N_BITS+1)];
};

typedef struct fss_key fss_key_t;


void DCF_gen(DTYPE_t alpha, uint8_t *s0, uint8_t *s1, size_t s_len, fss_key_t *k0, fss_key_t *k1);

DTYPE_t DCF_eval(bool b, fss_key_t *kb, DTYPE_t x);