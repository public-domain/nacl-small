/* NaCl-like encrypt+MAC for small MCUs
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, 27 Dec 2013
 *
 * This file is in the public domain.
 */

#ifndef CRYPTO_BOX_H_
#define CRYPTO_BOX_H_

#include <stdint.h>
#include <stddef.h>

/* NOTE: these functions will not work with messages larger than
 * (1 MB - 32 bytes). They assume that the index of each keystream block
 * can be fit into a 16-bit integer.
 *
 * If you need longer messages, you can modify the implementation easily
 * (at the expense of slightly increased memory use).
 */

#define CRYPTO_BOX_KEY_SIZE		32
#define CRYPTO_BOX_NONCE_SIZE		8
#define CRYPTO_BOX_AUTH_SIZE		16

/* Encrypt (Salsa20) and MAC (Poly1305) a message using the given key
 * and nonce. The message is XORed with the keystream and an
 * authenticator is written to a.
 */
void crypto_box(uint8_t *m, size_t len, uint8_t *a,
		const uint8_t *k, const uint8_t *n);

/* Verify and decrypt. Returns 0 on success or non-zero if the
 * authenticator is invalid.
 */
uint8_t crypto_box_open(uint8_t *m, size_t len, const uint8_t *a,
			const uint8_t *k, const uint8_t *n);

#define CRYPTO_BOX_XNONCE_SIZE		16

/* XSalsa20: Take the first 16 bytes of nonce and a key, and derive a
 * subkey. Use this subkey with the remaining 8 bytes of nonce.
 *
 * s and k may point to the same location.
 */
void crypto_xsalsa20_subkey(uint8_t *s, const uint8_t *k, const uint8_t *n);

#endif
