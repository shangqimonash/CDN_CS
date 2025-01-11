//
// Created by Shangqi on 15/8/21.
//

#ifndef PHM_BLOCK_H
#define PHM_BLOCK_H

#include <immintrin.h>
#include <openssl/rand.h>

typedef __m128i block;

#define zero_block() _mm_setzero_si128()
#define block_equal(x,y) (_mm_movemask_epi8(_mm_cmpeq_epi8(x,y)) == 0xffff)
#define block_xor(x,y) _mm_xor_si128(x,y)
#define block_lsb(x) (*((uint8_t *) &(x)) & 1)

#define dpf_lsb(x) (*((char *) &x) & 1)


#define make_block(x, y) _mm_set_epi64((__m64)(x), (__m64)(y))  // create a 128-bit block with two 64-bit integer

#define block_left_shift(v, n)                  \
({                                              \
    __m128i v1, v2;                             \
                                                \
    if ((n) >= 64)                              \
    {                                           \
        v1 = _mm_slli_si128(v, 8);              \
        v1 = _mm_slli_epi64(v1, (n) - 64);      \
    }                                           \
    else                                        \
    {                                           \
        v1 = _mm_slli_epi64(v, n);              \
        v2 = _mm_slli_si128(v, 8);              \
        v2 = _mm_srli_epi64(v2, 64 - (n));      \
        v1 = _mm_or_si128(v1, v2);              \
        }                                       \
    v1;                                         \
})

inline void
random_block(block *out)
{
    RAND_bytes((uint8_t*) out, sizeof(block));
}

inline
block reverse_lsb(block input){
    static long long b1 = 0;
    static long long b2 = 1;
    block  mask = make_block(b1, b2);
    return block_xor(input, mask);
}



inline 
block dpf_set_lsb_zero(block input){
	int lsb = dpf_lsb(input);

	if(lsb == 1){
		return reverse_lsb(input);	
	}else{
		return input;
	}
}

#endif //PHM_BLOCK_H
