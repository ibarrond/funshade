#include "aes.h"

const uint8_t iv_aes_128[AES_BLOCKLEN]  = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

//----------------------------------------------------------------------------//
//--------------------------- PRIVATE - AES_TINY -----------------------------//
//----------------------------------------------------------------------------//
// PRIVATE VARIABLES & TYPES
struct AES_ctx{uint8_t RoundKey[AES_keyExpSize];};

// state - array holding the intermediate results during decryption.
typedef uint8_t state_t[4][4];

// The lookup-tables are marked const so they can be placed in read-only storage instead of RAM
// The numbers below can be computed dynamically trading ROM for RAM - 
// This can be useful in (embedded) bootloader applications, where ROM is often limited.
static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

// The round constant word array, Rcon[i], contains the values given by 
// x to the power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };


// PRIVATE FUNCTIONS
#define getSBoxValue(num) (sbox[(num)])

// This function produces Nb(Nr+1) round keys. The round keys are used in each round to decrypt the states. 
static void KeyExpansion(uint8_t* RoundKey, const uint8_t* Key)
{
  unsigned i, j, k;
  uint8_t tempa[4]; // Used for the column/row operations
  for (i = 0; i < Nk; ++i){// The first round key is the key itself.
    RoundKey[(i * 4) + 0] = Key[(i * 4) + 0]; RoundKey[(i * 4) + 1] = Key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = Key[(i * 4) + 2]; RoundKey[(i * 4) + 3] = Key[(i * 4) + 3];
  }
  for (i = Nk; i < Nb * (Nr + 1); ++i){ // All other round keys are found from the previous round keys.
    k = (i - 1) * 4;
    tempa[0]=RoundKey[k + 0]; tempa[1]=RoundKey[k + 1];
    tempa[2]=RoundKey[k + 2]; tempa[3]=RoundKey[k + 3];
    if (i % Nk == 0) {
      // shifts the 4 bytes in a word to the left once.
      const uint8_t u8tmp = tempa[0];
      tempa[0] = tempa[1]; tempa[1] = tempa[2]; tempa[2] = tempa[3]; tempa[3] = u8tmp;
      // Takes a four-byte input word and applies the S-box to each byte.
      tempa[0] = getSBoxValue(tempa[0]); tempa[1] = getSBoxValue(tempa[1]);
      tempa[2] = getSBoxValue(tempa[2]); tempa[3] = getSBoxValue(tempa[3]);
      tempa[0] = tempa[0] ^ Rcon[i/Nk];
    }
    j = i * 4; k=(i - Nk) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

static void AES_init_ctx(struct AES_ctx* ctx, const uint8_t* key)
    {KeyExpansion(ctx->RoundKey, key);}

// This function adds the round key to state.
// The round key is added to the state by an XOR function.
static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey){
  uint8_t i,j;
  for (i = 0; i < 4; ++i){
    for (j = 0; j < 4; ++j){
      (*state)[i][j] ^= RoundKey[(round * Nb * 4) + (i * Nb) + j];}}}

// The SubBytes Function Substitutes the values in the
// state matrix with values in an S-box.
static void SubBytes(state_t* state){
  uint8_t i, j;
  for (i = 0; i < 4; ++i){
    for (j = 0; j < 4; ++j){
      (*state)[j][i] = getSBoxValue((*state)[j][i]);}}}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
static void ShiftRows(state_t* state){
  uint8_t temp;
  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1]; (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1]; (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;
  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2]; (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;
  temp           = (*state)[1][2]; (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;
  // Rotate third row 3 columns to left
  temp           = (*state)[0][3]; (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3]; (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;}

static uint8_t xtime(uint8_t x){return ((x<<1) ^ (((x>>7) & 1) * 0x1b));}

// MixColumns function mixes the columns of the state matrix
static void MixColumns(state_t* state){
  uint8_t i, Tmp, Tm, t;
  for (i = 0; i < 4; ++i){  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;}}

// Multiply is used to multiply numbers in the field GF(2^8)
#define Multiply(x, y)                                \
      (  ((y & 1) * x) ^                              \
      ((y>>1 & 1) * xtime(x)) ^                       \
      ((y>>2 & 1) * xtime(xtime(x))) ^                \
      ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^         \
      ((y>>4 & 1) * xtime(xtime(xtime(xtime(x))))))   \

// Cipher is the main function that encrypts the PlainText.
static void Cipher(state_t* state, const uint8_t* RoundKey){
  uint8_t round = 0;
  // Add the First round key to the state before starting the rounds.
  AddRoundKey(0, state, RoundKey);
  // There will be Nr rounds. The first Nr-1 rounds are identical (below)
  for (round = 1; ; ++round){
    SubBytes(state);  ShiftRows(state);
    if (round == Nr) {break;}
    MixColumns(state);AddRoundKey(round, state, RoundKey);}
  // Add round key to last round
  AddRoundKey(Nr, state, RoundKey);}

static void aes128_tiny_enc_ecb(const uint8_t *enc_key, const uint8_t *plainText, uint8_t *cipherText){
  struct AES_ctx ctx;
  memcpy(cipherText, plainText, AES_BLOCKLEN);
  AES_init_ctx(&ctx, enc_key);
  Cipher((state_t*)cipherText, ctx.RoundKey);}


//----------------------------------------------------------------------------//
//---------------------------- PRIVATE AES_NI --------------------------------//
//----------------------------------------------------------------------------//
#ifdef __AES__
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
#endif

//----------------------------------------------------------------------------//
//--------------------------------- PUBLIC -----------------------------------//
//----------------------------------------------------------------------------//
void MP_owf_aes128_tiny(
  const uint8_t key_in[AES_BLOCKLEN],
  const uint8_t msg_in[AES_BLOCKLEN],
  uint8_t msg_out[AES_BLOCKLEN])
{
    size_t j;
    aes128_tiny_enc_ecb(key_in,msg_in,msg_out);      // AES-128
    for (j = 0; j < AES_BLOCKLEN; j++) {             // XOR3
        msg_out[j] = key_in[j] ^ msg_in[j] ^ msg_out[j];
    }
}
#ifdef __AES__
void MP_owf_aes128_ni(
  const uint8_t key_in[AES_BLOCKLEN],
  const uint8_t msg_in[AES_BLOCKLEN],
  uint8_t msg_out[AES_BLOCKLEN])
{
    size_t j;
    aes128_ni_enc_ecb(key_in,msg_in,msg_out);       // AES-128
    for (j = 0; j < AES_BLOCKLEN; j++) {            // XOR3
        msg_out[j] = key_in[j] ^ msg_in[j] ^ msg_out[j];
    }
}
#endif


void G_tiny(const uint8_t buffer_in[], uint8_t buffer_out[],
           size_t buffer_in_size, size_t buffer_out_size){
    size_t i;
    assertm(buffer_in_size==AES_BLOCKLEN, "buffer_in must be of 16 bytes (128 bits)");
    assertm(buffer_out_size%AES_BLOCKLEN==0, "buffer_out must be a multiple of 16 bytes");
    // Process first block with IV as key
    MP_owf_aes128_tiny(iv_aes_128, buffer_in, buffer_out);
    // Process remaining blocks, using previous block as key
    for (i = AES_BLOCKLEN; i < buffer_out_size; i+=AES_BLOCKLEN){
        MP_owf_aes128_tiny(&buffer_out[i-AES_BLOCKLEN],buffer_in,&buffer_out[i]);
    }
}
#ifdef __AES__
void G_ni(const uint8_t buffer_in[], uint8_t buffer_out[],
           size_t buffer_in_size, size_t buffer_out_size){
    size_t i;
    assertm(buffer_in_size==AES_BLOCKLEN, "buffer_in must be of 16 bytes (128 bits)");
    assertm(buffer_out_size%AES_BLOCKLEN==0, "buffer_out must be a multiple of 16 bytes");
    // Process first block with IV as key
    MP_owf_aes128_ni(iv_aes_128, buffer_in, buffer_out);
    // Process remaining blocks, using previous block as key
    for (i = AES_BLOCKLEN; i < buffer_out_size; i+=AES_BLOCKLEN){
        MP_owf_aes128_ni(&buffer_out[i-AES_BLOCKLEN], buffer_in, &buffer_out[i]);
    }
}
#endif