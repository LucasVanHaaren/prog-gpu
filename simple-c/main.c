#include <stdint.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "../includes/config.h"
#include "md4.h"

const uint32_t MD4_INIT_A = 0x67452301;
const uint32_t MD4_INIT_B = 0xefcdab89;
const uint32_t MD4_INIT_C = 0x98badcfe;
const uint32_t MD4_INIT_D = 0x10325476;


unsigned char precomputed_paddings[MAX_LEN - MIN_LEN + 1][64];


void precompute_paddings() {
  for (int len = MIN_LEN; len <= MAX_LEN; len++) {
      unsigned char buffer[64];
      memset(buffer, 0, 64); 

      buffer[len] = 0x80;

      uint32_t bit_len = len * 8;
      buffer[56] = bit_len & 0xFF;
      buffer[57] = (bit_len >> 8) & 0xFF;
      buffer[58] = (bit_len >> 16) & 0xFF;
      buffer[59] = (bit_len >> 24) & 0xFF;

      memcpy(precomputed_paddings[len - MIN_LEN], buffer, 64);
  }
}

void MD4_Init(MD4_CTX *ctx) {
  memset(ctx->buffer, 0, 64);
  ctx->A = MD4_INIT_A;
  ctx->B = MD4_INIT_B;
  ctx->C = MD4_INIT_C;
  ctx->D = MD4_INIT_D;
  ctx->lo = 0;
  ctx->hi = 0;

  ctx->buffer[57] = 0;
  ctx->buffer[58] = 0;
  ctx->buffer[59] = 0;
}


void MD4_AllInOne(const unsigned char *data, unsigned long size, unsigned char *out, MD4_CTX *ctx) {
  // Init Phase
  ctx->lo = size;
  ctx->hi = 0;


  memcpy(ctx->buffer, data, size);
  // I put the padding myself

  ctx->buffer[size++] = 0x80;// Padding

  // I fill with 0 after the padding

  memset(&ctx->buffer[size], 0, 64 - size - 8); // The - 8 is because last 8 bytes are for the size of the data
  uint32_t bit_len = (uint32_t)(ctx->lo << 3);

  ctx->buffer[56] = bit_len;

  // I call the body function

  body(ctx, (const MD4_u32plus *)ctx->buffer, 64); // Going to shake everything

  // I write the output (Final STEP to)
  out[0]  = ctx->A;
  out[1]  = ctx->A >> 8;
  out[2]  = ctx->A >> 16;
  out[3]  = ctx->A >> 24;
  out[4]  = ctx->B;
  out[5]  = ctx->B >> 8;
  out[6]  = ctx->B >> 16;
  out[7]  = ctx->B >> 24;
  out[8]  = ctx->C;
  out[9]  = ctx->C >> 8;
  out[10] = ctx->C >> 16;
  out[11] = ctx->C >> 24;
  out[12] = ctx->D;
  out[13] = ctx->D >> 8;
  out[14] = ctx->D >> 16;
  out[15] = ctx->D >> 24;

}


int incr_candidate(char *ptr, int *current_len) {
    ssize_t pos = *current_len - 1;
    while (1) {
        if (pos < 0) { // We have done all the possibilities in my case it's between 'a' and 'z'
            if (*current_len < MAX_LEN) { // 
                ptr[*current_len] = '\0'; // We add at the end of the data '\0'
                (*current_len)++;
                return 1;
            }
            return 0;
        }
        char c = ++ptr[pos]; // a -> b -> c -> ... -> z
        if (c > 'z') { // Just in case if we go more than z we go back to a
            ptr[pos] = 'a';
            pos--; // We go to the next character on the left
        } else {
            return 1;
        }
    }
}


int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s HASH\n", argv[0]);
    return -1;
  }
  unsigned char *target = parse_hash(argv[1]);
  if (!target) {
      fprintf(stderr, "[X] - Error parsing hash\n");
      return -1;
  }
    
  char *candidate = malloc(MAX_LEN + 1);

  if (!candidate) {
      fprintf(stderr, "[X] - Error malloc\n");
      free(target);
      return -1;
  }

  memset(candidate, 'a', MIN_LEN);
  candidate[MIN_LEN] = '\0';

  MD4_CTX base_ctx;
  MD4_Init(&base_ctx);


  struct timeval tval;
  double start;
  double now;

  gettimeofday(&tval, NULL);
  start = tval.tv_sec + tval.tv_usec / 1000000.0;

  unsigned char res[16]; // Store the result of the hash
  int current_len = MIN_LEN;
  size_t tested = 0;

  do {
     
      MD4_CTX temp_ctx = base_ctx;

      MD4_AllInOne((unsigned char *)candidate, current_len, res, &temp_ctx);
      //printf("candidate: %s\n", candidate);
      tested++;

      if (memcmp(res, target, 16) == 0) {
          printf("found: %s, after %ld tries\n", candidate, tested);
          free(candidate);
          free(target);
          return 0;
      }

      if (tested % (1024 * 1024 * 32) == 0) {
          gettimeofday(&tval, NULL);
          now = tval.tv_sec + tval.tv_usec / 1000000.0;
          double speed = tested / (now - start);
          fprintf(stderr, "%.3f M/s\n", speed / 1000000.0);
      }
  } while (incr_candidate(candidate, &current_len));

  printf("not found after %ld tries\n", tested);
  free(candidate);
  free(target);
  return 1;
}