#ifndef _CONFIG_H_
#define _CONFIG_H_

#include <stdint.h>     //for int8_t
#include <assert.h>     //for assert


#define USE_LIBSODIUM

// Assert with message
#define assertm(exp, msg) assert(((void)msg, exp))


#endif // _CONFIG_H_
