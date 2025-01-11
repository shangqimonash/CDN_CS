//
// https://www.cs.virginia.edu/~cr4bd/3330/S2018/simdref.html
//

#ifndef PHM_AES_H
#define PHM_AES_H

#include "Block.h"

typedef struct { block rd_key[11]; unsigned int rounds; } AES_KEY;

#define EXPAND_ASSIST(v1,v2,v3,v4,shuff_const,aes_const)                \
v2 = _mm_aeskeygenassist_si128(v4,aes_const);                           \
v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
_mm_castsi128_ps(v1), 16));                                             \
v1 = _mm_xor_si128(v1,v3);                                              \
v3 = _mm_castps_si128(_mm_shuffle_ps(_mm_castsi128_ps(v3),              \
_mm_castsi128_ps(v1), 140));                                            \
v1 = _mm_xor_si128(v1,v3);                                              \
v2 = _mm_shuffle_epi32(v2,shuff_const);                                 \
v1 = _mm_xor_si128(v1,v2)


inline static void
AES_export_encrypt_key( const AES_KEY * key, int * key_arr, unsigned int *rounds) //ensure key_arr = 44 int arr
{
    for(int index = 0; index < 11; index++) {
        __m128i values = key->rd_key[index];
        key_arr[4 * index] = _mm_extract_epi32(values, 0);
        key_arr[4 * index + 1] = _mm_extract_epi32(values, 1);
        key_arr[4 * index + 2] = _mm_extract_epi32(values, 2);
        key_arr[4 * index + 3] = _mm_extract_epi32(values, 3);

    }

    *rounds = key->rounds;
}

inline static void
AES_import_encrypt_key(  AES_KEY * key, const int * key_arr, const unsigned int rounds) //import key_arr = 44 and round
{
    key->rounds = rounds;

    for(int index = 0; index < 11; index++) {
        __m128i values = _mm_setr_epi32(key_arr[4*index], key_arr[4*index + 1 ], key_arr[4*index + 2 ], key_arr[4*index + 3 ]);
        key->rd_key[index] = values;
    }    
}


inline static void
AES_set_encrypt_key(const block userkey, AES_KEY * __restrict__ key)
{
    block x0, x1, x2;
    block *kp = key->rd_key;
    kp[0] = x0 = userkey;
    x2 = _mm_setzero_si128();
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 1);
    kp[1] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 2);
    kp[2] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 4);
    kp[3] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 8);
    kp[4] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 16);
    kp[5] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 32);
    kp[6] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 64);
    kp[7] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 128);
    kp[8] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 27);
    kp[9] = x0;
    EXPAND_ASSIST(x0, x1, x2, x0, 255, 54);
    kp[10] = x0;
    key->rounds = 10;
}

inline static void
AES_ecb_encrypt_blks(block * __restrict__ blks, unsigned int nblks, const AES_KEY * __restrict__ key)
{
    for (unsigned int i = 0; i < nblks; ++i)
        blks[i] = _mm_xor_si128(blks[i], key->rd_key[0]);
    for (unsigned int j = 1; j < key->rounds; ++j)
        for (unsigned int i = 0; i < nblks; ++i)
            blks[i] = _mm_aesenc_si128(blks[i], key->rd_key[j]);
        for (unsigned int i = 0; i < nblks; ++i)
            blks[i] = _mm_aesenclast_si128(blks[i], key->rd_key[key->rounds]);
}

inline static void
AES_set_decrypt_key_fast(AES_KEY * __restrict__ dkey, const AES_KEY * __restrict__ ekey)
{
    int j = 0;
    int i = ekey->rounds;
#if (OCB_KEY_LEN == 0)
    dkey->rounds = i;
#endif
    dkey->rd_key[i--] = ekey->rd_key[j++];
    while (i)
        dkey->rd_key[i--] = _mm_aesimc_si128(ekey->rd_key[j++]);
    dkey->rd_key[i] = ekey->rd_key[j];
}

inline static void
AES_set_decrypt_key(const block userkey, AES_KEY * __restrict__ key)
{
    AES_KEY temp_key;
    AES_set_encrypt_key(userkey, &temp_key);
    AES_set_decrypt_key_fast(key, &temp_key);
}

inline static void
AES_ecb_decrypt_blks(block * __restrict__ blks, unsigned nblks, const AES_KEY * __restrict__ key)
{
    unsigned i, j, rnds = key->rounds;
    for (i = 0; i < nblks; ++i)
        blks[i] = _mm_xor_si128(blks[i], key->rd_key[0]);
    for (j = 1; j < rnds; ++j)
        for (i = 0; i < nblks; ++i)
            blks[i] = _mm_aesdec_si128(blks[i], key->rd_key[j]);
        for (i = 0; i < nblks; ++i)
            blks[i] = _mm_aesdeclast_si128(blks[i], key->rd_key[j]);
}

#endif //PHM_AES_H
