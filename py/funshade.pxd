
from libc.stdint cimport int64_t, int64_t, uint8_t

cdef extern from "fss/fss.h" nogil:
    ctypedef DTYPE_t DTYPE_t
    cdef size_t S_LEN
    cdef size_t SEED_LEN
    cdef size_t CW_CHAIN_LEN

    cdef struct ic_key:
        uint8_t s[S_LEN]
        uint8_t CW_chain[CW_CHAIN_LEN]
        DTYPE_t z

    DTYPE_t random_dtype()                                   
    DTYPE_t random_dtype_seeded(const uint8_t seed[SEED_LEN])

    void random_buffer(uint8_t buffer[], size_t buffer_len)   
    void random_buffer_seeded(uint8_t buffer[], size_t buffer_len, const uint8_t seed[SEED_LEN])

    void DCF_gen       (DTYPE_t alpha, struct ic_key *k0, struct ic_key *k1)
    void DCF_gen_seeded(DTYPE_t alpha, struct ic_key *k0, struct ic_key *k1, uint8_t s0[S_LEN], uint8_t s1[S_LEN])
    DTYPE_t DCF_eval(bool b, struct ic_key *kb, DTYPE_t x_hat)

    void IC_gen(DTYPE_t r_in, DTYPE_t r_out, DTYPE_t p, DTYPE_t q, struct ic_key *k0_ic, struct ic_key *k1_ic)
    DTYPE_t IC_eval(bool b, DTYPE_t p, DTYPE_t q, struct ic_key *kb_ic, DTYPE_t x_hat)

    void SIGN_gen(DTYPE_t r_in, DTYPE_t r_out, struct ic_key *k0, struct ic_key *k1)
    DTYPE_t SIGN_eval(bool b, struct ic_key *kb_ic, DTYPE_t x_hat)