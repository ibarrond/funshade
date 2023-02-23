#include "aes_ni.h"

const uint8_t iv_aes_ni[AES_BLOCKLEN]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

//----------------------------------------------------------------------------//
//-------------------------------- PRIVATE -----------------------------------//
//----------------------------------------------------------------------------//
static __m128i aes_128_key_expansion(__m128i key, __m128i keygened){
    keygened = _mm_shuffle_epi32(keygened, _MM_SHUFFLE(3,3,3,3));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
    return _mm_xor_si128(key, keygened);
}

static void aes128_gen_key_schedule(const uint8_t *enc_key, __m128i *key_schedule){
    key_schedule[0] = _mm_loadu_si128((const __m128i*) enc_key);
    key_schedule[1]  = AES_128_key_exp(key_schedule[0], 0x01);
    key_schedule[2]  = AES_128_key_exp(key_schedule[1], 0x02);
    key_schedule[3]  = AES_128_key_exp(key_schedule[2], 0x04);
    key_schedule[4]  = AES_128_key_exp(key_schedule[3], 0x08);
    key_schedule[5]  = AES_128_key_exp(key_schedule[4], 0x10);
    key_schedule[6]  = AES_128_key_exp(key_schedule[5], 0x20);
    key_schedule[7]  = AES_128_key_exp(key_schedule[6], 0x40);
    key_schedule[8]  = AES_128_key_exp(key_schedule[7], 0x80);
    key_schedule[9]  = AES_128_key_exp(key_schedule[8], 0x1B);
    key_schedule[10] = AES_128_key_exp(key_schedule[9], 0x36);
}

static void aes128_enc(__m128i *key_schedule, const uint8_t *plainText,uint8_t *cipherText){
    __m128i m = _mm_loadu_si128((__m128i *) plainText);
    // DO_ENC_BLOCK(m,key_schedule);
    m = _mm_xor_si128       (m, key_schedule[ 0]);  m = _mm_aesenc_si128    (m, key_schedule[ 1]);
    m = _mm_aesenc_si128    (m, key_schedule[ 2]);  m = _mm_aesenc_si128    (m, key_schedule[ 3]);
    m = _mm_aesenc_si128    (m, key_schedule[ 4]);  m = _mm_aesenc_si128    (m, key_schedule[ 5]);
    m = _mm_aesenc_si128    (m, key_schedule[ 6]);  m = _mm_aesenc_si128    (m, key_schedule[ 7]);
    m = _mm_aesenc_si128    (m, key_schedule[ 8]);  m = _mm_aesenc_si128    (m, key_schedule[ 9]);
    m = _mm_aesenclast_si128(m, key_schedule[10]);
    _mm_storeu_si128((__m128i *) cipherText, m);
}

static void aes128_ni_enc_ecb(const uint8_t *enc_key, const uint8_t *plainText,uint8_t *cipherText){
    __m128i key_schedule[11];
    aes128_gen_key_schedule(enc_key, key_schedule);
    aes128_enc(key_schedule, plainText, cipherText);
}


//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//
void MP_owf_aes128_ni(
    const uint8_t key_in[AES_BLOCKLEN],
    const uint8_t msg_in[AES_BLOCKLEN],
    uint8_t msg_out[AES_BLOCKLEN]){
    aes128_ni_enc_ecb(key_in,msg_in,msg_out);      // AES-128 encryption
    for (size_t j = 0; j < AES_BLOCKLEN; j++) {    // XOR3
        msg_out[j] = key_in[j] ^ msg_in[j] ^ msg_out[j];
    }
}

void G_ni(const uint8_t buffer_in[], uint8_t buffer_out[],
           size_t buffer_in_size, size_t buffer_out_size){
    assertm(buffer_in_size==AES_BLOCKLEN, "buffer_in must be of 16 bytes (128 bits)");
    assertm(buffer_out_size%AES_BLOCKLEN==0, "buffer_out must be a multiple of 16 bytes");
    // Process first block with IV as key
    MP_owf_aes128_ni(iv_aes_ni,buffer_in,buffer_out);
    // Process remaining blocks, using previous block as key
    for (size_t i = AES_BLOCKLEN; i < buffer_out_size; i+=AES_BLOCKLEN){
        MP_owf_aes128_ni(&buffer_out[i-AES_BLOCKLEN], buffer_in, &buffer_out[i]);
    }
}