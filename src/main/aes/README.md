# Portable C implementation of the AES block cipher
This is a portable C implementation of the AES block cipher. 

The faster version with AES-NI instructions comes from https://github.com/sebastien-riou/aes-brute-force/blob/master/include/aes_ni.h

The standalone version comes from https://github.com/kokke/tiny-AES-c/blob/master/aes.h

The AES-NI should be compiled with `-maes` flag, whereas both versions should be compiled with `-O3` and `-march=native` flags (GCC).