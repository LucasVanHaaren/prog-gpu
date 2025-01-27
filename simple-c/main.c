#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>

#include "../includes/config.h"
#include "md4.h"

// OPTI : avoid compute too much times
#define EXP (1024 * 1024 * 32)
#define ARCH_ALLOWS_UNALIGNED 1

int main(int argc, char **argv) {
  
  if (argc != 2) {
    fprintf(stderr, "Usage: %s HASH\n", argv[0]);
    return -1;
  }

  unsigned char *target = parse_hash(argv[1]);
  char *candidate = malloc(PWD_LEN + 1);
  memset(candidate, '!', PWD_LEN);
  candidate[PWD_LEN] = 0;
  size_t tested = 0;
  struct timeval tval;
  double start;
  double now;

  gettimeofday(&tval, NULL);
  start = tval.tv_sec + tval.tv_usec / 1000000.0;
  MD4_CTX ctx;
  do {
    // init MD4 context
    ctx.A = 0x67452301;
    ctx.B = 0xefcdab89;
    ctx.C = 0x98badcfe;
    ctx.D = 0x10325476;
    ctx.lo = 0;
    ctx.hi = 0;

    // update MD4 context
    MD4_u32plus saved_lo;
    saved_lo = ctx.lo;
    if ((ctx.lo = (saved_lo + PWD_LEN) & 0x1fffffff) < saved_lo)
        ctx.hi++;
    memcpy(ctx.buffer, candidate, PWD_LEN);
    unsigned long used, free;
    used = ctx.lo & 0x3f;
    ctx.buffer[used++] = 0x80;
    free = 64 - used;
    memset(&ctx.buffer[used], 0, free);
    ctx.buffer[64-8] = PWD_LEN * 8;
    body(&ctx, &ctx.buffer);
    unsigned char digest[16];
    memcpy(digest, &ctx.A, 4);
    memcpy(digest+4, &ctx.B, 4);
    memcpy(digest+8, &ctx.C, 4);
    memcpy(digest+12, &ctx.D, 4);

    tested++;
    
    if (memcmp(digest, target, 16) == 0) {
      printf("found: %s, after %ld tries\n", candidate, tested);
      return 0;
    }

    if (tested % EXP == 0) {
      gettimeofday(&tval, NULL);
      now = tval.tv_sec + tval.tv_usec / 1000000.0;
      double speed = tested / (now - start);
      fprintf(stderr, "%.3f M/s\n", speed / 1000000.0);
    }
  } while (incr_candidate(candidate));
  
  printf("not found after %ld tries\n", tested);
  
  return 1;
}