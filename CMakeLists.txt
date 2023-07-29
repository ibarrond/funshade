cmake_minimum_required(VERSION 3.14)
project(funshade)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_C_STANDARD 90)

###############################################################################
## target definitions #########################################################
###############################################################################

add_compile_options(-O3 -msse -msse2 -maes -march=native -Wall -Wextra)
# add_compile_definitions(USE_LIBSODIUM) # Use libsodium for cryptographically secure RNG
# add_compile_definitions(USE_PARALLEL)  # Use OpenMP for parallelization
include_directories(.)
link_libraries(sodium)
# link_libraries(gomp)

# # Build shared library
# add_library(funshade SHARED ${sources})
# set_target_properties(funshade PROPERTIES SOVERSION 1)
# set_target_properties(funshade PROPERTIES PUBLIC_HEADER src/main/fss.h)
add_executable(test_fss funshade/c/test_fss.c funshade/c/fss.c funshade/c/aes.c)