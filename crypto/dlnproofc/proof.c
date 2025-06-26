// File: crypto/dlnproofc/proof.c
#include "proof.h"
#include <gmp.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ITERATIONS 128

void set_mpz_from_bytes(mpz_t rop, const uint8_t *buf, size_t len) {
  mpz_import(rop, len, 1, 1, 1, 0, buf);
}

void get_mpz_to_bytes(mpz_t op, uint8_t *buf, size_t len) {
  size_t count;
  uint8_t *out = (uint8_t *)mpz_export(NULL, &count, 1, 1, 1, 0, op);
  size_t offset = len > count ? len - count : 0;
  memset(buf, 0, offset);
  memcpy(buf + offset, out, count);
  free(out);
}

int dln_verify(const uint8_t *h1_buf, size_t h1_len, const uint8_t *h2_buf,
               size_t h2_len, const uint8_t *n_buf, size_t n_len,
               const uint8_t **alpha_bufs, const uint8_t **t_bufs,
               size_t int_len, const uint8_t *hash_buf) {
  mpz_t h1, h2, N, alpha, t, h1_exp_t, rhs, tmp;
  mpz_inits(h1, h2, N, alpha, t, h1_exp_t, rhs, tmp, NULL);

  set_mpz_from_bytes(h1, h1_buf, h1_len);
  set_mpz_from_bytes(h2, h2_buf, h2_len);
  set_mpz_from_bytes(N, n_buf, n_len);

  for (int i = 0; i < ITERATIONS; i++) {
    set_mpz_from_bytes(alpha, alpha_bufs[i], int_len);
    set_mpz_from_bytes(t, t_bufs[i], int_len);

    mpz_powm(h1_exp_t, h1, t, N);

    if ((hash_buf[i / 8] >> (i % 8)) & 1) {
      mpz_mul(rhs, alpha, h2);
    } else {
      mpz_set(rhs, alpha);
    }
    mpz_mod(rhs, rhs, N);

    if (mpz_cmp(h1_exp_t, rhs) != 0) {
      mpz_clears(h1, h2, N, alpha, t, h1_exp_t, rhs, tmp, NULL);
      return 0; // false
    }
  }

  mpz_clears(h1, h2, N, alpha, t, h1_exp_t, rhs, tmp, NULL);
  return 1; // true
}

int dln_prove(const uint8_t *h1_buf, size_t h1_len, const uint8_t *x_buf,
              size_t x_len, const uint8_t *p_buf, size_t p_len,
              const uint8_t *q_buf, size_t q_len, const uint8_t *n_buf,
              size_t n_len, const uint8_t *hash_buf, uint8_t **alpha_out,
              uint8_t **t_out, size_t out_len) {
  // Input validation
  if (!alpha_out || !t_out) {
    return 0;
  }

  mpz_t h1, x, p, q, N, pq, r, alpha, tmp, t;
  mpz_inits(h1, x, p, q, N, pq, r, alpha, tmp, t, NULL);

  set_mpz_from_bytes(h1, h1_buf, h1_len);
  set_mpz_from_bytes(x, x_buf, x_len);
  set_mpz_from_bytes(p, p_buf, p_len);
  set_mpz_from_bytes(q, q_buf, q_len);
  set_mpz_from_bytes(N, n_buf, n_len);

  mpz_mul(pq, p, q);

  gmp_randstate_t state;
  gmp_randinit_default(state);

  // Better seeding - use current time and process info
  unsigned long seed = (unsigned long)time(NULL) ^ (unsigned long)getpid();
  gmp_randseed_ui(state, seed);

  for (int i = 0; i < ITERATIONS; i++) {
    // Validate output buffers
    if (!alpha_out[i] || !t_out[i]) {
      mpz_clears(h1, x, p, q, N, pq, r, alpha, tmp, t, NULL);
      gmp_randclear(state);
      return 0;
    }

    mpz_urandomm(r, state, pq); // r in [0, pq)
    mpz_powm(alpha, h1, r, N);
    get_mpz_to_bytes(alpha, alpha_out[i], out_len);

    mpz_set(t, r);
    if ((hash_buf[i / 8] >> (i % 8)) & 1) {
      // Fixed: directly add x instead of multiplying by 1
      mpz_add(t, t, x);
    }
    mpz_mod(t, t, pq);
    get_mpz_to_bytes(t, t_out[i], out_len);
  }

  mpz_clears(h1, x, p, q, N, pq, r, alpha, tmp, t, NULL);
  gmp_randclear(state);
  return 1;
}