// Based on https://github.com/kokke/tiny-AES-c/blob/master/aes.h
#ifndef _AES_STANDALONE_H_
#define _AES_STANDALONE_H_

#include <stdint.h> // uint8_t
#include <stddef.h> // size_t
#include <string.h> // memcpy

// Block length in bytes, base AES is 128b block.
//  The standalone AEs can be switched to 192 or 256 bit keys (requires changing more defines)
//  The NI version is fixed at 128 bit keys
#define AES_BLOCKLEN 16 

#include "config.h"
static const uint8_t iv[AES_BLOCKLEN]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

//----------------------------------------------------------------------------//
//-------------------------------- PRIVATE -----------------------------------//
//----------------------------------------------------------------------------//

// #define the macros below to 1/0 to enable/disable the mode of operation.

#define AES128 1
//#define AES192 1
//#define AES256 1

#define AES_BLOCKLEN 16 // Block length in bytes - AES is 128b block only

#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16   // Key length in bytes
    #define AES_keyExpSize 176
#endif

struct AES_ctx
{
  uint8_t RoundKey[AES_keyExpSize];
};

void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key);

// buffer size is exactly AES_BLOCKLEN bytes; 
// you need only AES_init_ctx as IV is not used in ECB 
// NB: ECB is considered insecure for most uses
void AES_SA_encrypt(const struct AES_ctx* ctx, uint8_t* buf);


//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//

/*  MP_block: Miyaguchi–Preneel one-way compression function with AES-128 (AES-NI)
    Input:  key_in  (16 bytes)
            msg_in  (16 bytes)
    Output: msg_out (16 bytes)
*/
void MP_owf_aes128_standalone(const uint8_t key_in[], const uint8_t msg_in[], uint8_t msg_out[]);

void G_sa(const uint8_t buffer_in[], uint8_t buffer_out[],
           size_t buffer_in_size, size_t buffer_out_size);
#endif // _AES_STANDALONE__H_