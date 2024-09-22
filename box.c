/* NaCl-like encrypt+MAC for small MCUs
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, 27 Dec 2013
 *
 * This file is in the public domain.
 */

#include <string.h>
#include "box.h"
#include "salsa20.h"
#include "poly1305.h"

static void ks_block(uint8_t *blk, const uint8_t *k, const uint8_t *n,
		     uint16_t i)
{
	crypto_salsa20_defconst(blk);
	crypto_salsa20_load_key(blk, k);

	/* Input nonce */
	memcpy(blk + 24, n, 8);

	/* Block index */
	blk[32] = i;
	blk[33] = i >> 8;
	memset(blk + 34, 0, 6);

	crypto_salsa20(blk, blk);
}

static void mix(uint8_t *dst, const uint8_t *src, uint8_t len)
{
	uint8_t i;

	for (i = 0; i < len; i++)
		dst[i] ^= src[i];
}

void crypto_box(uint8_t *m, size_t len, uint8_t *a,
		const uint8_t *k, const uint8_t *n)
{
	uint8_t ks[CRYPTO_SALSA20_OUTPUT_SIZE];

	ks_block(ks, k, n, 0);

	if (len <= 32) {
		mix(m, ks + 32, len);
	} else {
		size_t rem = len - 32;
		uint8_t *mm = m + 32;
		uint16_t i = 1;

		/* First 32 bytes */
		mix(m, ks + 32, 32);

		/* 64-byte blocks */
		while (rem > 64) {
			ks_block(ks, k, n, i++);
			mix(mm, ks, 64);

			mm += 64;
			rem -= 64;
		}

		/* Last <= 64 bytes */
		ks_block(ks, k, n, i);
		mix(mm, ks, rem);

		/* Restore block 0 for authenticator calculation */
		ks_block(ks, k, n, 0);
	}

	/* MAC, using (r, n) from first 32-bytes of keystream block 0 */
	crypto_poly1305_prepare_r(ks);
	crypto_poly1305_eval(a, ks, ks + 16, m, len);
}

uint8_t crypto_box_open(uint8_t *m, size_t len, const uint8_t *a,
			const uint8_t *k, const uint8_t *n)
{
	uint8_t ks[CRYPTO_SALSA20_OUTPUT_SIZE];

	ks_block(ks, k, n, 0);

	crypto_poly1305_prepare_r(ks);
	crypto_poly1305_eval(ks, ks, ks + 16, m, len);
	if (crypto_poly1305_compare(ks, a))
		return 1;

	if (len <= 32) {
		mix(m, ks + 32, len);
	} else {
		size_t rem = len - 32;
		uint8_t *mm = m + 32;
		uint16_t i = 1;

		/* First 32 bytes */
		mix(m, ks + 32, 32);

		/* 64-byte blocks */
		while (rem > 64) {
			ks_block(ks, k, n, i++);
			mix(mm, ks, 64);

			mm += 64;
			rem -= 64;
		}

		/* Last <= 64 bytes */
		ks_block(ks, k, n, i);
		mix(mm, ks, rem);
	}

	return 0;
}

void crypto_xsalsa20_subkey(uint8_t *s, const uint8_t *k, const uint8_t *n)
{
	uint8_t blk[CRYPTO_SALSA20_BLOCK_SIZE];

	crypto_salsa20_defconst(blk);
	crypto_salsa20_load_key(blk, k);
	crypto_salsa20_load_input(blk, n);
	crypto_hsalsa20(s, blk);
}
