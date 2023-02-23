// G: RNG function for Function Secret Sharing (FSS) with AES-128 standalone
// -----------------------------------------------------------------------------
// Public functions:
//  MP_owf_aes128_standalone: Miyaguchi–Preneel one-way function with AES-128 ECB mode
//  G_sa: RNG function for Function Secret Sharing (FSS) with AES-128 standalone
// 
// Author: Alberto Ibarrondo
//
// AES Based on https://github.com/kokke/tiny-AES-c/blob/master/aes.h

#ifndef _AES_TINY_H_
#define _AES_TINY_H_

#include <stdint.h> // uint8_t
#include <stddef.h> // size_t
#include <string.h> // memcpy
#include <assert.h> //for assert



// MACROS
// Block length in bytes, base AES is 128b block.
//  The standalone AEs can be switched to 192 or 256 bit keys (requires changing more defines)
//  The NI version is fixed at 128 bit keys
#define AES_BLOCKLEN 16
#define AES_keyExpSize 176
#define Nb 4
#define Nk 4        // The number of 32 bit words in a key.
#define Nr 10       // The number of rounds in AES Cipher.

// Assert with message
#define assertm(exp, msg) assert(((void)msg, exp))

const uint8_t iv_aes_tiny[AES_BLOCKLEN];


/*  MP_block: Miyaguchi–Preneel one-way compression function with AES-128 (AES-NI)
    Input:  key_in  (16 bytes)
            msg_in  (16 bytes)
    Output: msg_out (16 bytes)
*/
void MP_owf_aes128_standalone(const uint8_t key_in[], const uint8_t msg_in[], uint8_t msg_out[]);


/*  G: AES Pseudo-random generator, created as a Merkle–Damgård hash construction
       employing a Miyaguchi–Preneel one-way compression function with AES-128.
       More info in: https://en.wikipedia.org/wiki/One-way_compression_function
    Input:  buffer_in  (16 bytes)
    Output: buffer_out (16 bytes)
*/
void G_sa(const uint8_t buffer_in[], uint8_t buffer_out[], size_t buffer_in_size, size_t buffer_out_size);

#endif // _AES_STANDALONE__H_