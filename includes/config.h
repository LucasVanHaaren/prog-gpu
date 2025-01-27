#ifndef __CONFIG_H
#define CONFIG_H

#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define PWD_LEN 6
#define MIN_LEN 4
#define MAX_LEN 12

static unsigned char from_hex(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  else
    return 10 + c - 'a';
}

// returns the binary representation of an hex encoded string
static unsigned char *parse_hash(char *input)
{
  size_t ilen = strlen(input);
  if (ilen & 1)
  {
    fprintf(stderr, "Odd length for the input string\n");
    return NULL;
  }
  size_t olen = ilen / 2;
  unsigned char *out = malloc(olen);
  for (int i = 0; i < olen; i++)
  {
    char hc = input[i * 2];
    char lc = input[i * 2 + 1];
    out[i] = from_hex(hc) * 16 + from_hex(lc);
  }
  return out;
}

#endif