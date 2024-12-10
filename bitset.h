// Copyright 2019 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef __HERCULES_BITSET_H__
#define __HERCULES_BITSET_H__

#include "utils.h"
#include <assert.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>

/** Simple bit-set that keeps track of number of elements in the set. */
struct bitset {
	_Atomic unsigned int *bitmap;
	u32 num;
	_Atomic u32 num_set;
	_Atomic u32 max_set;
	pthread_spinlock_t lock;
};

#define HERCULES_BITSET_WORD_BITS (8 * sizeof(unsigned int))

int bitset__create(struct bitset *s, u32 num);

void bitset__destroy(struct bitset *s);

// Returns true iff the bit at index i in bitmap is set
static inline bool bitset__check(struct bitset *s, u32 i)
{
	assert(i < s->num);
	return (s->bitmap[i / HERCULES_BITSET_WORD_BITS]) & (1u << i % HERCULES_BITSET_WORD_BITS);
}

// set bit at index i in bitmap.
// Returns the previous state of the bit.
static inline bool bitset__set_mt_safe(struct bitset *s, u32 i)
{
	pthread_spin_lock(&s->lock);
	asm volatile("":::"memory"); // XXX why is this here?
	unsigned int bit = 1u << i % HERCULES_BITSET_WORD_BITS;
	unsigned int prev = atomic_fetch_or(&s->bitmap[i / HERCULES_BITSET_WORD_BITS], bit);
	if(!(prev & bit)) {
		atomic_fetch_add(&s->num_set, 1);
		u32 tmp_max = atomic_load(&s->max_set);
		while(tmp_max < i) {
			if(atomic_compare_exchange_weak(&s->max_set, &tmp_max, i)) {
				pthread_spin_unlock(&s->lock);
				return false;
			}
		}
		pthread_spin_unlock(&s->lock);
		return false;
	}
	asm volatile("":::"memory");
	pthread_spin_unlock(&s->lock);
	return true;
}

// set bit at index i in bitmap.
// This function is not thread-safe.
static inline bool bitset__set(struct bitset *s, u32 i)
{
	const bool prev = bitset__check(s, i);
	s->bitmap[i / HERCULES_BITSET_WORD_BITS] |= (1 << i % HERCULES_BITSET_WORD_BITS);
	if(!prev) {
		s->num_set++;
		if(s->max_set < i) {
			s->max_set = i;
		}
	}
	return prev;
}


// unset bit at index i in bitmap.
// Returns the previous state of the bit.
static inline bool bitset__unset(struct bitset *s, u32 i)
{
	const bool prev = bitset__check(s, i);
	s->bitmap[i / HERCULES_BITSET_WORD_BITS] &= ~(1u << i % HERCULES_BITSET_WORD_BITS);
	if(prev) {
		s->num_set--;
	}
	return prev;
}

// Reset the bitmap
// Unsets all entries in bitmap and reset the number of elements in the set
static inline void bitset__reset(struct bitset *s)
{
	// due to rounding, need to use the same formula as for allocation
	memset(s->bitmap, 0,
	       ((s->num + HERCULES_BITSET_WORD_BITS - 1) / HERCULES_BITSET_WORD_BITS) * (HERCULES_BITSET_WORD_BITS / 8));
	s->num_set = 0;
}

// Find next entry in the set.
// Returns lowest index i greater or equal than pos such that bit i is set, or
// s->num if no such index exists.
static inline u32 bitset__scan(struct bitset *s, u32 pos)
{
	// TODO: profile the entire application and rewrite this function to use bitscan ops
	if (s->num == 1 && pos == 0) {
		// Needed for the edge case where the bitset has only 1 entry
		return !bitset__check(s, 0);
	}
	for(u32 i = pos; i < s->max_set; ++i) {
		if(bitset__check(s, i)) {
			return i;
		}
	}
	return s->num;
}

// Find next entry NOT in the set.
// Returns lowest index i greater or equal than pos such that bit i is NOT set,
// or s->num if no such index exists.
static inline u32 bitset__scan_neg(struct bitset *s, u32 pos)
{
	for(u32 i = pos; i < s->num; ++i) {
		if(!bitset__check(s, i)) {
			return i;
		}
	}
	return s->num;
}

// Find nth entry NOT in the set.
// Returns nth lowest index i greater or equal than pos such that bit i is NOT set,
// or s->num if no such index exists.
static inline u32 bitset__scan_neg_n(struct bitset *s, u32 pos, u32 n)
{
	for(u32 i = pos; i < s->num; ++i) {
		if(!bitset__check(s, i)) {
			n--;
		}
		if(n == 0) {
			return i;
		}
	}
	return s->num;
}

#endif // __HERCULES_BITSET_H__
