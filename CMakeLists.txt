cmake_minimum_required(VERSION 3.14) # setting this is required
project(funshade)                    # this sets the project name

###############################################################################
## file globbing ##############################################################
###############################################################################

# These instructions search the directory tree when cmake is
# invoked and put all files that match the pattern in the variables 
# `sources` and `data`.
file(GLOB_RECURSE sources      src/main/*.c src/main/*.h)
file(GLOB_RECURSE sources_test src/test/test_fss.c)
# file(GLOB_RECURSE data resources/*)
# You can use set(sources src/main.cpp) etc if you don't want to
# use globbing to find files automatically.

###############################################################################
## target definitions #########################################################
###############################################################################

add_compile_options(-O3 -maes -march=native)

# Build shared library
add_library(funshade SHARED ${sources})
set_target_properties(funshade PROPERTIES SOVERSION 1)
set_target_properties(funshade PROPERTIES PUBLIC_HEADER src/main/fss.h)


add_executable(test ${sources_test})

# Just for example add some compiler flags.
target_compile_options(test PUBLIC )
target_include_directories(test PUBLIC src/main)
target_link_libraries(test PUBLIC funshade sodium)