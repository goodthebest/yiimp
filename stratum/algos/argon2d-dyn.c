#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sysendian.h"

#include "ar2/argon2.h"
#include "ar2/core.h"

#define T_COSTS 2
#define A_THREADS 1
#define M_COSTS 500
#define A_LANES 8
#define INPUT_BYTES 80
#define OUTPUT_BYTES 32
#define DEFAULT_ARGON2D_FLAG 2

inline void argon2d_call(void *in, void *out, const uint32_t len)
{
	argon2_context context;
	context.out = (uint8_t *)out;
	context.outlen = (uint32_t)OUTPUT_BYTES;
	context.pwd = (uint8_t *)in;
	context.pwdlen = (uint32_t)len;
	context.salt = (uint8_t *)in; //salt = input
	context.saltlen = (uint32_t)len;
	context.secret = NULL;
	context.secretlen = 0;
	context.ad = NULL;
	context.adlen = 0;
	context.allocate_cbk = NULL;
	context.free_cbk = NULL;
	context.flags = DEFAULT_ARGON2D_FLAG; // = ARGON2_DEFAULT_FLAGS
	// main configurable Argon2 hash parameters
	context.m_cost = M_COSTS;  // Memory in KiB
	context.lanes = A_LANES;	 // Degree of Parallelism
	context.threads = A_THREADS;   // Threads
	context.t_cost = T_COSTS;	// Iterations

	return argon2_ctx(&context, DEFAULT_ARGON2D_FLAG);
}

void argon2d_dyn_hash(const char* input, char* output, uint32_t len)
{
	argon2d_call(input, output, len);
}