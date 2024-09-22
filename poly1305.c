/* Poly1305 for small MCUs
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, 26 Dec 2013
 *
 * This file is in the public domain.
 */

#include <string.h>
#include "poly1305.h"

void crypto_poly1305_prepare_r(uint8_t *r)
{
	r[3] &= 15;
	r[4] &= 252;

	r[7] &= 15;
	r[8] &= 252;

	r[11] &= 15;
	r[12] &= 252;

	r[15] &= 15;
}

/* Add (2^(len * 8) + m) to x, modulo 2^136. This shouldn't overflow,
 * because the first term is 129 bits, and x is 131 bits.
 */
static void add_chunk(uint8_t *x, const uint8_t *m, uint8_t len)
{
	uint16_t c = 0;
	uint8_t i;

	/* Add message digits */
	for (i = 0; i < len; i++) {
		c += ((uint16_t)x[i]) + ((uint16_t)m[i]);
		x[i] = c;
		c >>= 8;
	}

	/* Leading 1 */
	c += ((uint16_t)x[i]) + 1;
	x[i++] = c;
	c >>= 8;

	/* Carry through */
	while (i < 17) {
		c += ((uint16_t)x[i]);
		x[i++] = c;
		c >>= 8;
	}
}

/* Multiply 17-byte x by 16-byte r, modulo p */
static void mul_modp(uint8_t *x, const uint8_t *r) __attribute__((noinline));

static void mul_modp(uint8_t *x, const uint8_t *r)
{
	uint8_t h[33];
	uint16_t c;
	uint8_t i;

	memset(h, 0, sizeof(h));

	/* Multiply 16-byte r and 17-byte x to produce 33-byte h */
	for (i = 0; i < 16; i++) {
		const uint8_t d = r[i];
		uint8_t j;

		/* h += d*x */
		c = 0;

		for (j = 0; j < 17; j++) {
			const uint16_t product = (uint16_t)d * (uint16_t)x[j];
			const uint8_t k = i + j;

			c += product + ((uint16_t)h[k]);
			h[k] = c;
			c >>= 8;
		}

		for (; j + i < 33; j++) {
			const uint8_t k = i + j;

			c += ((uint16_t)h[k]);
			h[k] = c;
			c >>= 8;
		}
	}

	/* Reduce h to a 138-bit number by folding the upper 16 bytes
	 * (b) into the lower 17 bytes (a) using the rule that 2^136 =
	 * 320 mod p:
	 *
	 *     h = a + 2^136*b
	 *       = a + 320*b (mod p)
	 *       = a + 2^8*b + 2^6*b
	 *
	 * We store the lower 130 bits in the lower 17 bytes of h and
	 * keep the upper 8 bits (c) for the next step.
	 */
	c = ((uint16_t)h[0]) + (((uint16_t)h[17]) << 6);
	h[0] = c;
	c >>= 8;

	for (i = 1; i < 16; i++) {
		c += h[i] +
		     ((uint16_t)h[i + 16]) +
		     (((uint16_t)h[i + 17]) << 6);
		h[i] = c;
		c >>= 8;
	}

	c += ((uint16_t)h[16]) + ((uint16_t)h[32]);
	h[16] = c & 3;
	c >>= 2;

	/* Reduce again, using 2^130 = 5 mod p:
	 *
	 *     h = a + 2^130*c
	 *       = a + 5*c (mod p)
	 *       = a + c + 2^2*c
	 *
	 * The final result is partially reduced. Since:
	 *
	 *       a <= 2^130 - 1
	 *       c <= 2^8 - 1
	 *     5*c <= 1275
	 *
	 * We have the end result:
	 *
	 *     x <= 2^130 + 1274
	 */
	c += (c << 2);

	for (i = 0; i < 17; i++) {
		c += ((uint16_t)h[i]);
		x[i] = c;
		c >>= 8;
	}
}

/* Add n to x, modulo 2^136. If we have the input conditions:
 *
 *     x <= 2^130 + 1274
 *     n <= 2^128 - 1
 *
 * Then we will have the output:
 *
 *     x + n < 2*p
 *
 * ...which can be fully reduced with one subtraction.
 */
static void add_nonce(uint8_t *x, const uint8_t *n)
{
	uint8_t i;
	uint16_t c = 0;

	for (i = 0; i < 16; i++) {
		c += ((uint16_t)x[i]) + ((uint16_t)n[i]);
		x[i] = c;
		c >>= 8;
	}

	x[16] = c;
}

/* Take partially reduced h < 2*p, and set out = h mod p. */
static void reduce(uint8_t *out, const uint8_t *h)
{
	uint16_t c;
	uint8_t i;
	uint8_t is_negative;

	/* Subtract p from h, modulo 2^136. But don't store the last
	 * byte, because out is only 16 bytes.
	 */
	c = 5;
	for (i = 0; i < 16; i++) {
		c += ((uint16_t)h[i]);
		out[i] = c;
		c >>= 8;
	}

	c += ((uint16_t)h[16]) - 4;
	is_negative = -((c >> 15) & 1);

	/* Select h if negative, (h-p) if not */
	for (i = 0; i < 16; i++)
		out[i] ^= is_negative & (h[i] ^ out[i]);
}

void crypto_poly1305_eval(uint8_t *out,
			  const uint8_t *r, const uint8_t *n,
			  const uint8_t *msg, size_t len)
{
	uint8_t h[17];

	memset(h, 0, sizeof(h));

	while (len > 16) {
		add_chunk(h, msg, 16);
		mul_modp(h, r);
		msg += 16;
		len -= 16;
	}

	if (len) {
		add_chunk(h, msg, len);
		mul_modp(h, r);
	}

	add_nonce(h, n);
	reduce(out, h);
}

uint8_t crypto_poly1305_compare(const uint8_t *a, const uint8_t *b)
{
	uint8_t x = 0;
	uint8_t i;

	for (i = 0; i < 16; i++)
		x |= a[i] ^ b[i];

	return x;
}
