/* Salsa20/HSalsa20 core functions for small MCUs
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, 27 Dec 2013
 *
 * This file is in the public domain.
 */

#ifndef CRYPTO_SALSA20_H_
#define CRYPTO_SALSA20_H_

#include <stdint.h>

/* The Salsa20 input block is an array of 16 32-bit little-endian words.
 * The output block is another array of 16 words.
 *
 * The input block is partitioned as follows:
 *
 *    C K K K K C I I I I C K K K K C
 *
 * Where C: constants, K: key, I: input.
 *
 * The I-words are usually partitoned further (in half) by the stream
 * implementation into an nonce and block counter.
 *
 * HSalsa20 is a variant which is used for subkey derivation in the
 * XSalsa20 stream cipher. Its output block is half the size of
 * Salsa20's.
 *
 * References:
 *
 *   Bernstein, D.J., "The Salsa20 Family of Stream Ciphers" (2007).
 *   URL: cr.yp.to/snuffle/salsafamily-20071225.pdf. Document ID:
 *   31364286077dcdff8e4509f9ff3139ad.
 *
 *   Bernstein, D.J., "Extending the Salsa20 Nonce" (2011). URL:
 *   cr.yp.to/snuffle/xsalsa-20110204.pdf. Document ID:
 *   c4b172305ff16e1429a48d9434d50e8a.
 */

#define CRYPTO_SALSA20_KEY_SIZE		32
#define CRYPTO_SALSA20_INPUT_SIZE	16
#define CRYPTO_SALSA20_CONST_SIZE	16
#define CRYPTO_SALSA20_BLOCK_SIZE	64

/* The default constant is the string "expand 32-byte k". This function
 * loads that into the input block.
 */
void crypto_salsa20_defconst(uint8_t *blk);

static inline void crypto_salsa20_load_const(uint8_t *blk, const uint8_t *c)
{
	memcpy(blk, c, 4);
	memcpy(blk + 20, c + 4, 4);
	memcpy(blk + 40, c + 8, 4);
	memcpy(blk + 60, c + 12, 4);
}

static inline void crypto_salsa20_load_input(uint8_t *blk, const uint8_t *in)
{
	memcpy(blk + 24, in, 16);
}

static inline void crypto_salsa20_load_key(uint8_t *blk, const uint8_t *key)
{
	memcpy(blk + 4, key, 16);
	memcpy(blk + 44, key + 16, 16);
}

/* Salsa20 PRF */

#define CRYPTO_SALSA20_OUTPUT_SIZE	64

void crypto_salsa20(uint8_t *out, const uint8_t *blk);

/* HSalsa20 PRF */

#define CRYPTO_HSALSA20_OUTPUT_SIZE	32

void crypto_hsalsa20(uint8_t *out, const uint8_t *blk);

#endif
