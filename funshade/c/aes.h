// G: RNG function for Function Secret Sharing (FSS) with AES-128
// -----------------------------------------------------------------------------
// Public functions:
//  - MP_owf_aes128_tiny: Miyaguchi–Preneel one-way function with AES-128 ECB mode.
//  - MP_owf_aes128_ni: Miyaguchi–Preneel one-way function with AES-NI.
//  - G_tiny: G hash function with AES-128 standalone.
//  - G_ni: G hash function with AES-128 (AES-NI).
// 
// Author: Alberto Ibarrondo
//
// AES-Tiny based on https://github.com/kokke/tiny-AES-c/blob/master/aes.h
// AES-NI Adapted from: https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
// If we ever need AES-NI 256 --> https://github.com/stong/bruteforce/blob/master/aes256_ecb.cpp
// Compile using gcc and following arguments: -O3;-msse2;-msse;-march=native;-maes

#ifndef __AES_H__
#define __AES_H__


#include <stdint.h>     //for int8_t
#include <stddef.h>     // size_t
#include <string.h>     //for memcmp
#include <assert.h>     //for assert

#ifdef __AES__
#include <wmmintrin.h>  //for intrinsics for AES-NI
#endif

// DEFINES
#define AES_BLOCKLEN 16         //  The NI version is fixed at 128 bit keys
#define assertm(exp, msg) assert(((void)msg, exp))      // Assert with message
//  -Tiny-
#define AES_keyExpSize 176
#define Nb 4
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.
//  -NI-
#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))

//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//
/*  MP_block: Miyaguchi–Preneel one-way compression function with AES-128. 
    There are two versions: _ni, using AES-NI instructions (faster, requires -maes
    flag), and _tiny, a standalone version (slower, portable).
    Input:  key_in  (AES_BLOCKLEN bytes)
            msg_in  (16 bytes)
    Output: msg_out (16 bytes)
*/
void MP_owf_aes128_tiny(const uint8_t key_in[AES_BLOCKLEN], 
                        const uint8_t msg_in[AES_BLOCKLEN],
                        uint8_t msg_out[AES_BLOCKLEN]);
#ifdef __AES__
void MP_owf_aes128_ni(const uint8_t key_in[AES_BLOCKLEN],
                      const uint8_t msg_in[AES_BLOCKLEN],
                      uint8_t msg_out[AES_BLOCKLEN]);
#endif // AES-NI

/*  G: AES Pseudo-random generator, created as a Merkle–Damgård hash construction
       employing a Miyaguchi–Preneel one-way compression function with AES-128.
       More info in: https://en.wikipedia.org/wiki/One-way_compression_function
    Input:  buffer_in  (16 bytes)
    Output: buffer_out (n*16 bytes) for n integer
*/
void G_tiny(const uint8_t buffer_in[],   uint8_t buffer_out[],
                   size_t buffer_in_size, size_t buffer_out_size);
#ifdef __AES__
void G_ni(const uint8_t buffer_in[],   uint8_t buffer_out[],
                 size_t buffer_in_size, size_t buffer_out_size);
#endif // AES-NI

#endif // __AES_H__