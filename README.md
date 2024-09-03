# Funshade
Functional Secret Sharing for Two-Party Secure Thresholded Distance Evaluation. 

- _Languages_: C (99+), Python (3.8+, for the wrapper)
- _Platforms_: Linux, Windows, MacOS (any system with a C compiler)
- _Dependencies_: `libsodium` (optional, for fast and secure random number generation)
- _Code Author_: Alberto Ibarrondo
- _License_: GNU GPLv3 (any code derived from this must be **open source**)
- _Version_: 1.1.0

### Description
Funshade is a library that implements a protocol to securely compute a distance metric between two vectors, followed by a secure comparison to a threshold. It is extremely lightweight, making use of cheap primitives such as AES and requiring a single intermediate round of communication and just two numbers sent per distance computation in the preprocessing model (besides input sharing and output reconstruction, common to all secret-sharing MPC schemes).

Consider citing the paper if you use it in your research!


### Installation
The library is written in plain C to make it **portable**.
It has been tested in Linux and Windows, but it should work in any system with a C compiler.
To compile it, you can:
- Use the provided CMakeLists.txt with `cmake`(`mkdir build && cd build && cmake .. & cmake --build .`)
- Directly call your compiler with the `-msse -msse2  -maes` flags for faster hardware-based AES acceleration (and consider `-O3 -march=native` for further optimizations). 

For conveniency and for seamless integration with higher-level languages, we also provide a Python wrapper.
Install it with:
- `pip install .`

As an optional dependency, it uses `libsodium` for fast and secure random number generation.

### Usage
The library is designed to be used as a black-box, with a simple API.

Check the bottom of `fss.h` for the available functions, `test_fss.c` for some uses in C, or `test_funshade.py` for a step-by-step Python example.


### Outside the scope of Funshade

- Additive secret sharing (refer to the [paper](https://hal.science/hal-04129231/), page 22 for further explanation on this scheme)