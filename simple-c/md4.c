#include "md4.h"
#include <string.h>
#include <stdio.h>

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

/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
#define STEP(f, a, b, c, d, n, s, data, size, constant) \
    do { \
        MD4_u32plus x = ((n) < ((size) / 4)) ? data[n] : (((n) == ((size) / 4)) ? 0x80 : 0); \
        (a) += f((b), (c), (d)) + x + (constant); \
        (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
    } while(0)
/*
 * SET reads 4 input bytes in little-endian byte order and stores them
 * in a properly aligned word in host byte order.
 *
 * The check for little-endian architectures that tolerate unaligned
 * memory accesses is just an optimization.  Nothing will break if it
 * doesn't work.
 */
// To remove
#define SET(n) \
	data[n]
#define GET(n) \
	SET(n)


/*
 * This processes one or more 64-byte data blocks, but does NOT update
 * the bit counters.  There are no alignment requirements.
 */
void body(MD4_CTX *ctx, const MD4_u32plus *data, unsigned long size)
{
    MD4_u32plus a, b, c, d;
    MD4_u32plus saved_a, saved_b, saved_c, saved_d;

    a = ctx->A;
    b = ctx->B;
    c = ctx->C;
    d = ctx->D;

    do {
        saved_a = a;
        saved_b = b;
        saved_c = c;
        saved_d = d;

        /* Round 1 */
        STEP(F, a, b, c, d, 0, 3, data, size, 0);
        STEP(F, d, a, b, c, 1, 7, data, size, 0);
        STEP(F, c, d, a, b, 2, 11, data, size, 0);
        STEP(F, b, c, d, a, 3, 19, data, size, 0);
        STEP(F, a, b, c, d, 4, 3, data, size, 0);
        STEP(F, d, a, b, c, 5, 7, data, size, 0);
        STEP(F, c, d, a, b, 6, 11, data, size, 0);
        STEP(F, b, c, d, a, 7, 19, data, size, 0);
        STEP(F, a, b, c, d, 8, 3, data, size, 0);
        STEP(F, d, a, b, c, 9, 7, data, size, 0);
        STEP(F, c, d, a, b, 10, 11, data, size, 0);
        STEP(F, b, c, d, a, 11, 19, data, size, 0);
        STEP(F, a, b, c, d, 12, 3, data, size, 0);
        STEP(F, d, a, b, c, 13, 7, data, size, 0);
        STEP(F, c, d, a, b, 14, 11, data, size, 0);
        STEP(F, b, c, d, a, 15, 19, data, size, 0);

        /* Round 2 */
        STEP(G, a, b, c, d, 0, 3, data, size, 0x5a827999);
        STEP(G, d, a, b, c, 4, 5, data, size, 0x5a827999);
        STEP(G, c, d, a, b, 8, 9, data, size, 0x5a827999);
        STEP(G, b, c, d, a, 12, 13, data, size, 0x5a827999);
        STEP(G, a, b, c, d, 1, 3, data, size, 0x5a827999);
        STEP(G, d, a, b, c, 5, 5, data, size, 0x5a827999);
        STEP(G, c, d, a, b, 9, 9, data, size, 0x5a827999);
        STEP(G, b, c, d, a, 13, 13, data, size, 0x5a827999);
        STEP(G, a, b, c, d, 2, 3, data, size, 0x5a827999);
        STEP(G, d, a, b, c, 6, 5, data, size, 0x5a827999);
        STEP(G, c, d, a, b, 10, 9, data, size, 0x5a827999);
        STEP(G, b, c, d, a, 14, 13, data, size, 0x5a827999);
        STEP(G, a, b, c, d, 3, 3, data, size, 0x5a827999);
        STEP(G, d, a, b, c, 7, 5, data, size, 0x5a827999);
        STEP(G, c, d, a, b, 11, 9, data, size, 0x5a827999);
        STEP(G, b, c, d, a, 15, 13, data, size, 0x5a827999);

        /* Round 3 */
        STEP(H, a, b, c, d, 0, 3, data, size, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 8, 9, data, size, 0x6ed9eba1);
        STEP(H, c, d, a, b, 4, 11, data, size, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 12, 15, data, size, 0x6ed9eba1);
        STEP(H, a, b, c, d, 2, 3, data, size, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 10, 9, data, size, 0x6ed9eba1);
        STEP(H, c, d, a, b, 6, 11, data, size, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 14, 15, data, size, 0x6ed9eba1);
        STEP(H, a, b, c, d, 1, 3, data, size, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 9, 9, data, size, 0x6ed9eba1);
        STEP(H, c, d, a, b, 5, 11, data, size, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 13, 15, data, size, 0x6ed9eba1);
        STEP(H, a, b, c, d, 3, 3, data, size, 0x6ed9eba1);
        STEP(H2, d, a, b, c, 11, 9, data, size, 0x6ed9eba1);
        STEP(H, c, d, a, b, 7, 11, data, size, 0x6ed9eba1);
        STEP(H2, b, c, d, a, 15, 15, data, size, 0x6ed9eba1);

        /* Ajouter les valeurs sauvegardées */
        a += saved_a;
        b += saved_b;
        c += saved_c;
        d += saved_d;

        /* Passer au bloc suivant */
        data += 16; // Avancer de 16 mots de 32 bits (64 octets)
        size -= 64;
    } while (size >= 64);

    /* Mettre à jour le contexte */
    ctx->A = a;
    ctx->B = b;
    ctx->C = c;
    ctx->D = d;
}
