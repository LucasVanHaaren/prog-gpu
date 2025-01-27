/*
 * This is an OpenSSL-compatible implementation of the RSA Data Security,
 * Inc. MD4 Message-Digest Algorithm (RFC 1320).
 *
 * Written by Solar Designer <solar at openwall.com> in 2001, and placed
 * in the public domain.  There's absolutely no warranty.
 *
 * This differs from Colin Plumb's older public domain implementation in
 * that no 32-bit integer data type is required, there's no compile-time
 * endianness configuration, and the function prototypes match OpenSSL's.
 * The primary goals are portability and ease of use.
 *
 * This implementation is meant to be fast, but not as fast as possible.
 * Some known optimizations are not included to reduce source code size
 * and avoid compile-time configuration.
 *
 * ... MD4_Final() has been modified in revision of this code found in the
 * JtR jumbo patch, dropping the memset() call.  You will likely want to undo
 * this change if you reuse the code for another purpose.  Or better yet,
 * download the original from:
 * http://openwall.info/wiki/people/solar/software/public-domain-source-code/md4
 */

#include "md4.h"
#include <string.h>

/*
 * The basic MD4 functions.
 *
 * F and G are optimized compared to their RFC 1320 definitions, with the
 * optimization for F borrowed from Colin Plumb's MD5 implementation.
 */
#define F(x, y, z)			((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)			(((x) & ((y) | (z))) | ((y) & (z)))
#define H(x, y, z)			(((x) ^ (y)) ^ (z))
#define H2(x, y, z)			((x) ^ ((y) ^ (z)))

/*
 * The MD4 transformation for all three rounds.
 */
#define STEP(f, a, b, c, d, x, s) \
	(a) += f((b), (c), (d)) + (x); \
	(a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s))));

static const MD4_u32plus ROUND2_CONSTANT = 0x5a827999;
static const MD4_u32plus ROUND3_CONSTANT = 0x6ed9eba1;

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
// #if ARCH_ALLOWS_UNALIGNED==1
#define SET(n) \
	(*(MD4_u32plus *)&ptr[(n) * 4])
#define GET(n) \
	SET(n)
// #else
// // permet de set un entier tout en swappant l'endianess
// // mais comme MD4 est faite pour du LE, et que nos systeme sont en LE on peux set le ARCH_ALLOW_ALIGNED
// #define SET(n) \
// 	(ctx->block[(n)] = \
// 	(MD4_u32plus)ptr[(n) * 4] | \
// 	((MD4_u32plus)ptr[(n) * 4 + 1] << 8) | \
// 	((MD4_u32plus)ptr[(n) * 4 + 2] << 16) | \
// 	((MD4_u32plus)ptr[(n) * 4 + 3] << 24))
// #define GET(n) \
// 	(ctx->block[(n)])
// #endif

/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */

#define BLOC_SIZE 64

const void *body(MD4_CTX *ctx, const void *data)
{
	unsigned const char *ptr;
	MD4_u32plus a, b, c, d;
	MD4_u32plus saved_a, saved_b, saved_c, saved_d;

	ptr = data;

	a = ctx->A;
	b = ctx->B;
	c = ctx->C;
	d = ctx->D;

	saved_a = a;
	saved_b = b;
	saved_c = c;
	saved_d = d;

	// STEP sert  a melanger les valeurs = rotate
	/* Round 1 */
	STEP(F, a, b, c, d, 0, 3)
	STEP(F, d, a, b, c, 1, 7)
	STEP(F, c, d, a, b, 2, 11)
	STEP(F, b, c, d, a, 3, 19)
	STEP(F, a, b, c, d, 4, 3)
	STEP(F, d, a, b, c, 5, 7)
	STEP(F, c, d, a, b, 6, 11)
	STEP(F, b, c, d, a, 7, 19)
	STEP(F, a, b, c, d, 8, 3)
	STEP(F, d, a, b, c, 9, 7)
	STEP(F, c, d, a, b, 10, 11)
	STEP(F, b, c, d, a, 11, 19)
	STEP(F, a, b, c, d, 12, 3)
	STEP(F, d, a, b, c, 13, 7)
	STEP(F, c, d, a, b, 14, 11)
	STEP(F, b, c, d, a, 15, 19)

/* Round 2 */
	STEP(G, a, b, c, d, GET(0) + ROUND2_CONSTANT, 3)
	STEP(G, d, a, b, c, GET(4) + ROUND2_CONSTANT, 5)
	STEP(G, c, d, a, b, GET(8) + ROUND2_CONSTANT, 9)
	STEP(G, b, c, d, a, GET(12) + ROUND2_CONSTANT, 13)
	STEP(G, a, b, c, d, GET(1) + ROUND2_CONSTANT, 3)
	STEP(G, d, a, b, c, GET(5) + ROUND2_CONSTANT, 5)
	STEP(G, c, d, a, b, GET(9) + ROUND2_CONSTANT, 9)
	STEP(G, b, c, d, a, GET(13) + ROUND2_CONSTANT, 13)
	STEP(G, a, b, c, d, GET(2) + ROUND2_CONSTANT, 3)
	STEP(G, d, a, b, c, GET(6) + ROUND2_CONSTANT, 5)
	STEP(G, c, d, a, b, GET(10) + ROUND2_CONSTANT, 9)
	STEP(G, b, c, d, a, GET(14) + ROUND2_CONSTANT, 13)
	STEP(G, a, b, c, d, GET(3) + ROUND2_CONSTANT, 3)
	STEP(G, d, a, b, c, GET(7) + ROUND2_CONSTANT, 5)
	STEP(G, c, d, a, b, GET(11) + ROUND2_CONSTANT, 9)
	STEP(G, b, c, d, a, GET(15) + ROUND2_CONSTANT, 13)

/* Round 3 */
	STEP(H, a, b, c, d, GET(0) + ROUND3_CONSTANT, 3)
	STEP(H2, d, a, b, c, GET(8) + ROUND3_CONSTANT, 9)
	STEP(H, c, d, a, b, GET(4) + ROUND3_CONSTANT, 11)
	STEP(H2, b, c, d, a, GET(12) + ROUND3_CONSTANT, 15)
	STEP(H, a, b, c, d, GET(2) + ROUND3_CONSTANT, 3)
	STEP(H2, d, a, b, c, GET(10) + ROUND3_CONSTANT, 9)
	STEP(H, c, d, a, b, GET(6) + ROUND3_CONSTANT, 11)
	STEP(H2, b, c, d, a, GET(14) + ROUND3_CONSTANT, 15)
	STEP(H, a, b, c, d, GET(1) + ROUND3_CONSTANT, 3)
	STEP(H2, d, a, b, c, GET(9) + ROUND3_CONSTANT, 9)
	STEP(H, c, d, a, b, GET(5) + ROUND3_CONSTANT, 11)
	STEP(H2, b, c, d, a, GET(13) + ROUND3_CONSTANT, 15)
	STEP(H, a, b, c, d, GET(3) + ROUND3_CONSTANT, 3)
	STEP(H2, d, a, b, c, GET(11) + ROUND3_CONSTANT, 9)
	STEP(H, c, d, a, b, GET(7) + ROUND3_CONSTANT, 11)
	STEP(H2, b, c, d, a, GET(15) + ROUND3_CONSTANT, 15)

	a += saved_a;
	b += saved_b;
	c += saved_c;
	d += saved_d;

	ptr += 64;

	ctx->A = a;
	ctx->B = b;
	ctx->C = c;
	ctx->D = d;

	return ptr;
}

// void MD4_Init(MD4_CTX *ctx)
// {
// 	ctx->A = 0x67452301;
// 	ctx->B = 0xefcdab89;
// 	ctx->C = 0x98badcfe;
// 	ctx->D = 0x10325476;

// 	ctx->lo = 0;
// 	ctx->hi = 0;
// }

void MD4_Update(MD4_CTX *ctx, const void *data, unsigned long size)
{
	MD4_u32plus saved_lo;
	unsigned long used, free;

	ctx->A = 0x67452301;
	ctx->B = 0xefcdab89;
	ctx->C = 0x98badcfe;
	ctx->D = 0x10325476;

	ctx->lo = 0;
	ctx->hi = 0;

	saved_lo = 0; // toujours 0
	// hi entre 6 et 12
	// pour fiare une addition de 2 fois 32 bits 
	if ((ctx->lo = (saved_lo + size) & 0x1fffffff) < saved_lo)
		ctx->hi++;
	ctx->hi += size >> 29;

	used = saved_lo & 0x3f;

	if (used) {
		free = 64 - used;

		if (size < free) {
			memcpy(&ctx->buffer[used], data, size);
			return;
		}

		memcpy(&ctx->buffer[used], data, free);
		data = (unsigned char *)data + free;
		size -= free;
		body(ctx, ctx->buffer);
	}
	memcpy(ctx->buffer, data, size);
}

void MD4_Final(unsigned char *result, MD4_CTX *ctx)
{
	unsigned long used, free;

	used = ctx->lo & 0x3f;

	ctx->buffer[used++] = 0x80; // octet de padding

	free = 64 - used;

	if (free < 8) {
		memset(&ctx->buffer[used], 0, free);
		body(ctx, ctx->buffer);
		used = 0;
		free = 64;
	}

	memset(&ctx->buffer[used], 0, free - 8);

	ctx->lo <<= 3;
	ctx->buffer[56] = ctx->lo;
	ctx->buffer[57] = ctx->lo >> 8;
	ctx->buffer[58] = ctx->lo >> 16;
	ctx->buffer[59] = ctx->lo >> 24;
	ctx->buffer[60] = ctx->hi;
	ctx->buffer[61] = ctx->hi >> 8;
	ctx->buffer[62] = ctx->hi >> 16;
	ctx->buffer[63] = ctx->hi >> 24;

	body(ctx, ctx->buffer);

	result[0] = ctx->A;
	result[1] = ctx->A >> 8;
	result[2] = ctx->A >> 16;
	result[3] = ctx->A >> 24;
	result[4] = ctx->B;
	result[5] = ctx->B >> 8;
	result[6] = ctx->B >> 16;
	result[7] = ctx->B >> 24;
	result[8] = ctx->C;
	result[9] = ctx->C >> 8;
	result[10] = ctx->C >> 16;
	result[11] = ctx->C >> 24;
	result[12] = ctx->D;
	result[13] = ctx->D >> 8;
	result[14] = ctx->D >> 16;
	result[15] = ctx->D >> 24;

#if 0
	memset(ctx, 0, sizeof(*ctx));
#endif
}
