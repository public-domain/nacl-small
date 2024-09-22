/* Poly1305 for small MCUs
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, 26 Dec 2013
 *
 * This file is in the public domain.
 */

#ifndef CRYPTO_POLY1305_H_
#define CRYPTO_POLY1305_H_

#include <stdint.h>
#include <stddef.h>

/* Poly1305 is a one-time message authentication code. Given a string of
 * bytes, and a pair of secret 128-bit numbers (r, n), it produces a
 * 128-bit authentication code.
 *
 * It does this by splitting the message into chunks of 128 bits, each
 * prepended with a leading '1'. These are treated as coefficients of a
 * polynomial, starting from the highest power down to x^1. The
 * coefficient of x^0 is n. This polynomial is then evaluated at r,
 * modulo the prime (2^130-5), and the lower 128 bits of the result are
 * returned.
 *
 * The numbers (r, n) must be secret, and n must never be reused.
 *
 * For more details, see:
 *
 *   Bernstein, D.J., "The Poly1305-AES message-authentication code"
 *   (2005). URL: http://cr.yp.to/mac/poly1305-20050329.pdf. Document
 *   ID: 0018d9551b5546d97c340e0dd8cb5750.
 *
 * Although the paper above uses AES with a secret key as a means of
 * generating a sequence of unique secret n-values, any cipher will do.
 */

#define CRYPTO_POLY1305_R_SIZE		16
#define CRYPTO_POLY1305_N_SIZE		16
#define CRYPTO_POLY1305_KEY_SIZE	32
#define CRYPTO_POLY1305_AUTH_SIZE	16

/* The number r must have certain bits set to 0. This function masks of
 * the necessary parts.
 */
void crypto_poly1305_prepare_r(uint8_t *r);

/* Compute a MAC, given (r, n) and a message string. */
void crypto_poly1305_eval(uint8_t *out,
			  const uint8_t *r, const uint8_t *n,
			  const uint8_t *msg, size_t len);

/* Compare two MACs in constant (not input-dependent) time. */
uint8_t crypto_poly1305_compare(const uint8_t *a, const uint8_t *b);

#endif
