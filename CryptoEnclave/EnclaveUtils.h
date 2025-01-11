#ifndef ENCLAVE_UTILS_H
#define ENCLAVE_UTILS_H

#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <iterator>
#include <vector>
#include <array>
#include <cstring>
#include "../common/data_type.h"
#include "SpookyHash/SpookyV2.h"
#include "DPF/DPF.h"

void printf( const char *fmt, ...);
void print_bytes(uint8_t *ptr, uint32_t len);
int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len);
void clear(uint8_t *dest, uint32_t len);
std::vector<std::string>  wordTokenize(char *content,int content_length);

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext, size_t ciphertext_len);
void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len);
int hash_SHA128(const void *key, const void *msg, int msg_len, void *value);
int hash_SHA128_key(const void *key, int key_len, const void *msg, int msg_len, void *value);

void tag_gen_key_counter(const void *key,const uint32_t counter,  char *tag1, char *tag2);
void tag_gen_key_counter_oblivBatch(const void *key,const uint32_t counter,  char *tag);

void hash_SHA_BlockSize(const void *key,const uint32_t counter, char *k_enc);
void block_enc_xor_counter(const unsigned char * masterK,  const std::string key,  const uint32_t counter, const char*plaintext, char *ciphertext);

void dump_tags_testing(const metaRangeRet_p1 * obj1, const metaRangeRet_p2 * obj2);
//void to_bytes(const AVLIndexNode& object, unsigned char* des);
//void from_bytes(const unsigned char* res, AVLIndexNode& object);

//improved
//void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, entryKey *k );
//void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, entryValue *v);
//void prf_Dec_Improve(const void *key,const void *ciphertext,size_t ciphertext_len, entryValue *value );

uint32_t u8_to_u32(const uint8_t* bytes);
void u32_to_u8(const uint32_t u32, uint8_t* u8);
uint32_t genHashBlockId(std::string c_id, int v_id, int dataset_size);

//for DPF
void inner_product_bit(const  unsigned char * content, const bool t, unsigned char *m , int len_size);
int dpf_getsize(const uint8_t *k);
void dpf_block_test(int oramindex, int index);
void dpf_auto_test(int index);

void dpf_gen_serialise( int oramIndex, int index, 
                       int *key_arr, unsigned int *rounds, 
                       uint8_t* p1, uint8_t* p2);

bool dpf_evaluate_index(const int *key_arr_prg, unsigned int rounds_prg, const uint8_t* p, int index);

void dpf_deserialised_test(const int oramIndex, const int * aes_k_p1, const unsigned int round_p1, const uint8_t *ks_p1,
                            int  index,
                            const int * aes_k_p2, const unsigned int round_p2, const uint8_t *ks_p2);  

void _output_bit_to_bit(uint64_t input);
void dpf_cb(block input);


void swap(uint32_t *a, uint32_t *b);
void permute(uint32_t * arr, int size);
uint32_t findIndexOfValue(uint32_t *permute,  uint32_t size, uint32_t value);
#endif
