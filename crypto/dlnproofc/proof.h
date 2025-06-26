#ifndef PROOF_H
#define PROOF_H

#include <gmp.h>
#include <stdint.h>
#include <stdlib.h>

void set_mpz_from_bytes(mpz_t rop, const uint8_t *buf, size_t len);
void get_mpz_to_bytes(mpz_t op, uint8_t *buf, size_t len);
int dln_verify(const uint8_t *h1_buf, size_t h1_len, const uint8_t *h2_buf,
               size_t h2_len, const uint8_t *n_buf, size_t n_len,
               const uint8_t **alpha_bufs, const uint8_t **t_bufs,
               size_t int_len, const uint8_t *hash_buf);
int dln_prove(const uint8_t *h1_buf, size_t h1_len, const uint8_t *x_buf,
              size_t x_len, const uint8_t *p_buf, size_t p_len,
              const uint8_t *q_buf, size_t q_len, const uint8_t *n_buf,
              size_t n_len, const uint8_t *hash_buf, uint8_t **alpha_out,
              uint8_t **t_out, size_t out_len);

#endif // PROOF_H