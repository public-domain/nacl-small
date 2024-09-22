/* Crypto functions for small MCUs (tests)
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, 26 Dec 2013
 *
 * This file is in the public domain.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include "box.h"

#define MAX_MSG		512

struct tv {
	uint8_t key[CRYPTO_BOX_KEY_SIZE];
	uint8_t nonce[CRYPTO_BOX_XNONCE_SIZE + CRYPTO_BOX_NONCE_SIZE];
	uint8_t subkey[CRYPTO_BOX_KEY_SIZE];
	uint8_t auth[CRYPTO_BOX_AUTH_SIZE];

	uint8_t plain[MAX_MSG];
	size_t	plen;

	uint8_t cipher[MAX_MSG];
	size_t	clen;
};

static size_t parse_arg(uint8_t *out, size_t max_len, const char *line)
{
	size_t count = 0;
	int byte = -1;

	assert(line[0] && line[1]);
	line += 2;

	while (*line) {
		char c = *(line++);
		int digit = -1;

		if ((c >= '0') && (c <= '9'))
			digit = c - '0';
		else if ((c >= 'A') && (c <= 'F'))
			digit = c - 'A' + 10;
		else if ((c >= 'a') && (c <= 'f'))
			digit = c - 'a' + 10;

		if (digit < 0)
			break;

		if (byte < 0) {
			byte = digit;
		} else {
			assert(count < max_len);

			out[count++] = (byte << 4) | digit;
			byte = -1;
		}
	}

	return count;
}

static void test(const struct tv *t)
{
	uint8_t buf[MAX_MSG];
	uint8_t auth[CRYPTO_BOX_AUTH_SIZE];
	uint8_t r = 0;

	assert(t->plen == t->clen);
	printf("Length: %d\n", (int)t->plen);

	/* Check subkey derivation */
	crypto_xsalsa20_subkey(buf, t->key, t->nonce);
	assert(!memcmp(buf, t->subkey, sizeof(t->subkey)));

	/* Check generation of ciphertext and authentication */
	memcpy(buf, t->plain, t->plen);
	crypto_box(buf, t->plen, auth,
		   t->subkey, t->nonce + CRYPTO_BOX_XNONCE_SIZE);

	assert(!memcmp(buf, t->cipher, t->clen));
	assert(!memcmp(auth, t->auth, sizeof(t->auth)));

	/* Check rejection of bad authenticators */
	auth[0] ^= 1;
	r = crypto_box_open(buf, t->clen, auth,
			    t->subkey, t->nonce + CRYPTO_BOX_XNONCE_SIZE);
	auth[0] ^= 1;

	assert(r);
	assert(!memcmp(buf, t->cipher, t->clen));

	/* Check decryption */
	r = crypto_box_open(buf, t->clen, auth,
			    t->subkey, t->nonce + CRYPTO_BOX_XNONCE_SIZE);

	assert(!r);
	assert(!memcmp(buf, t->plain, t->plen));
}

int main(void)
{
	char line[1024];
	struct tv t;

	memset(&t, 0, sizeof(t));

	while (fgets(line, sizeof(line), stdin)) {
		size_t len;

		switch (line[0]) {
		case 'K':
			len = parse_arg(t.key, sizeof(t.key), line);
			assert(len == sizeof(t.key));
			break;

		case 'N':
			len = parse_arg(t.nonce, sizeof(t.nonce), line);
			assert(len == sizeof(t.nonce));
			break;

		case 'S':
			len = parse_arg(t.subkey, sizeof(t.subkey), line);
			assert(len == sizeof(t.subkey));
			break;

		case 'P':
			t.plen = parse_arg(t.plain, sizeof(t.plain), line);
			break;

		case 'C':
			t.clen = parse_arg(t.cipher, sizeof(t.cipher), line);
			break;

		case 'A':
			len = parse_arg(t.auth, sizeof(t.auth), line);
			assert(len == sizeof(t.auth));
			break;

		case '\n':
			test(&t);
			memset(&t, 0, sizeof(t));
			break;
		}
	}

	return 0;
}
