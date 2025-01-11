//
// Created by Shangqi on 12/8/21.
//

#ifndef PHM_DPF_H
#define PHM_DPF_H

#include <cstring>

#include "../common/AES.h"

uint8_t get_bit(int x, int length, int b);

bool test_bit_n(const block &value, int n);

bool test_bit(const block* input, int n);

void output_bit_to_bit(uint64_t input, uint8_t* output_bit);

void print_block(block input,  uint8_t* bit1, uint8_t* bit2) ;

void new_PRG(AES_KEY *key, block input, block* output1, block* output2, int* bit1, int* bit2);

void PRG(const AES_KEY* key, block input, block* output1, block* output2, uint8_t* bit1, uint8_t* bit2);

void new_gen(AES_KEY *key, int alpha, int n, unsigned char** k0, unsigned char **k1);

void dpf_gen(int alpha, int n,
             const AES_KEY* key,
             uint8_t* &k0, uint8_t* &k1);

block new_eval(AES_KEY *key, unsigned char* k, int x);

block* new_eval_full( AES_KEY *key,  unsigned char* k);


bool dpf_eval_tag(const AES_KEY* key, const uint8_t* k, int x);

block dpf_eval(const AES_KEY* key, const uint8_t* k, int x);

block* dpf_eval_full(const AES_KEY* key,
                      const uint8_t* k);


block dpf_eval_full_tag(const AES_KEY* key,
                      const uint8_t* k);

#endif //PHM_DPF_H
