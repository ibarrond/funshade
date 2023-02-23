// G: RNG function for Function Secret Sharing (FSS) with AES-128 (AES-NI)
// -----------------------------------------------------------------------------
// Public functions:
//  MP_owf_aes128_ni: Miyaguchi–Preneel one-way compression function with AES-128 (AES-NI)
//  G_ni: G hash function with AES-128 (AES-NI)
// 
// Author: Alberto Ibarrondo
//
// AES Adapted from: https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h
// If we ever need AES256 --> https://github.com/stong/bruteforce/blob/master/aes256_ecb.cpp
// Compile using gcc and following arguments: -O3;-msse2;-msse;-march=native;-maes

#ifndef __AES_NI_H__
#define __AES_NI_H__


#include <stdint.h>     //for int8_t
#include <string.h>     //for memcmp
#include <wmmintrin.h>  //for intrinsics for AES-NI
#include <assert.h>     //for assert

// MACROS
#define AES_BLOCKLEN 16         //  The NI version is fixed at 128 bit keys
#define AES_128_key_exp(k, rcon) aes_128_key_expansion(k, _mm_aeskeygenassist_si128(k, rcon))
#define assertm(exp, msg) assert(((void)msg, exp))      // Assert with message

// Initialization Vector, can be set to arbitrary 16 bytes.
const uint8_t iv_aes_ni[AES_BLOCKLEN];

//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//

/*  MP_block: Miyaguchi–Preneel one-way compression function with AES-128 (AES-NI)
    Input:  key_in  (16 bytes)
            msg_in  (16 bytes)
    Output: msg_out (16 bytes)
*/
void MP_owf_aes128_ni(
    const uint8_t key_in[AES_BLOCKLEN],
    const uint8_t msg_in[AES_BLOCKLEN],
    uint8_t msg_out[AES_BLOCKLEN]);

/*  G: AES Pseudo-random generator, created as a Merkle–Damgård hash construction
       employing a Miyaguchi–Preneel one-way compression function with AES-128.
       More info in: https://en.wikipedia.org/wiki/One-way_compression_function
    Input:  buffer_in  (16 bytes)
    Output: buffer_out (16 bytes)
*/
void G_ni(
    const uint8_t buffer_in[],
    uint8_t buffer_out[],
    size_t buffer_in_size,
    size_t buffer_out_size);

#endif