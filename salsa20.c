/* Salsa20/HSalsa20 core functions for small MCUs
 *
 * Author: Daniel Beer <dlbeer@gmail.com>, 31 Dec 2013
 *
 * This file is in the public domain.
 */

#include <string.h>
#include "salsa20.h"

static inline uint32_t load(const uint8_t *x)
{
	return ((uint32_t)x[0]) |
	       (((uint32_t)x[1]) << 8) |
	       (((uint32_t)x[2]) << 16) |
	       (((uint32_t)x[3]) << 24);
}

static inline void store(uint8_t *x, uint32_t y)
{
	x[0] = y;
	x[1] = y >> 8;
	x[2] = y >> 16;
	x[3] = y >> 24;
}

static inline uint32_t rotate(uint32_t x, int i)
{
	return (x << i) | (x >> (32 - i));
}

/* Construct one function for each rotation distance. On the AVR, this
 * seems to be the most economial way. GCC by default tries to inline
 * these functions at higher optimization levels, and that causes the
 * stack usage to blow out.
 */
#define DECLARE_OP(r) \
	static void op##r(uint32_t *x, uint8_t a, uint8_t b, uint8_t d) \
		__attribute__((noinline)); \
	static void op##r(uint32_t *x, uint8_t a, uint8_t b, uint8_t d) \
	{ \
		x[d] ^= rotate(x[a] + x[b], r); \
	}

DECLARE_OP(7);
DECLARE_OP(9);
DECLARE_OP(13);
DECLARE_OP(18);

/* This describes the set of operations performed on each column group:
 *
 *     C(diagonal, below, below_below, above)
 *     R(src_a, src_b, rotation, dst)
 */
#define C(a, b, c, d) \
	R(a, d, 7, b) \
	R(b, a, 9, c) \
	R(c, b, 13, d) \
	R(d, c, 18, a)

/* This is a list of the column groups operated on in one double-round.
 * The first four groups are columns, the last four are rows. Each group
 * starts with the diagonal element and cycles around.
 */
#define COLUMN_LIST \
	C(0, 4, 8, 12) \
	C(5, 9, 13, 1) \
	C(10, 14, 2, 6) \
	C(15, 3, 7, 11) \
	C(0, 1, 2, 3) \
	C(5, 6, 7, 4) \
	C(10, 11, 8, 9) \
	C(15, 12, 13, 14)

/* Perform one double-round */
static void dround(uint32_t *x)
{
#define R(a, b, r, d) op##r(x, a, b, d);
	COLUMN_LIST
#undef R
}

/* Perform 20 rounds (10 double-rounds) */
static inline void core(uint32_t *x)
{
	uint8_t i;

	for (i = 0; i < 10; i++)
		dround(x);
}

static inline void load_work(uint32_t *x, const uint8_t *blk)
{
	uint8_t i;

	for (i = 0; i < 16; i++) {
		const uint8_t j = i << 2;

		x[i] = load(blk + j);
	}
}

static void add_final(uint8_t *out, const uint8_t *blk, const uint32_t *x)
{
	uint8_t i;

	for (i = 0; i < 16; i++) {
		const uint8_t j = i << 2;

		store(out + j, x[i] + load(blk + j));
	}
}

void crypto_salsa20(uint8_t *out, const uint8_t *blk)
{
	uint32_t x[16];

	load_work(x, blk);
	core(x);
	add_final(out, blk, x);
}

static void store_const(uint8_t *out, const uint32_t *x)
{
	uint8_t i, j = 0;

	for (i = 0; i < 16; i += 4) {
		store(out + i, x[j]);
		j += 5;
	}
}

static void store_in(uint8_t *out, const uint32_t *x)
{
	uint8_t i;

	for (i = 0; i < 4; i++) {
		const uint8_t j = i << 2;

		store(out + j, x[i + 6]);
	}
}

void crypto_hsalsa20(uint8_t *out, const uint8_t *blk)
{
	uint32_t x[16];

	load_work(x, blk);
	core(x);
	store_const(out, x);
	store_in(out + 16, x);
}

void crypto_salsa20_defconst(uint8_t *blk)
{
	blk[ 0] = 'e';
	blk[ 1] = 'x';
	blk[ 2] = 'p';
	blk[ 3] = 'a';
	blk[20] = 'n';
	blk[21] = 'd';
	blk[22] = ' ';
	blk[23] = '3';
	blk[40] = '2';
	blk[41] = '-';
	blk[42] = 'b';
	blk[43] = 'y';
	blk[60] = 't';
	blk[61] = 'e';
	blk[62] = ' ';
	blk[63] = 'k';
}
