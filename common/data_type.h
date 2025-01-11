#ifndef DATA_TYPE_H
#define DATA_TYPE_H

#include "config.h"
#include <stdint.h>
#include <vector>
#include <algorithm>
#include <array>
#include <list>
#include <string>
#include <tuple>
#include <utility>

static unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

#define AESGCM_MAC_SIZE 16
#define ENC_KEY_SIZE 16 // for AES128
#define ENTRY_VALUE_LEN 128 // 1024-bit
#define ENTRY_HASH_KEY_LEN_128 16 // for HMAC-SHA128- bit key
#define ENC_KEY_SIZE32 32
#define AESGCM_IV_SIZE 12


typedef struct
{
    uint32_t path; //oram path 
    uint32_t bu; //bucket level
    uint32_t offset; //offset in the bucket
    char enc_content[VIDEO_BLOCK_SIZE];
} meta_enc_block; //used to export between ecall and ocall for Stash Upload

typedef struct
{
    uint32_t path; //oram path 
    uint32_t bu; //bucket level
    uint32_t offset; //offset in the bucket
} blockPos; //used to export between ecall and ocall



typedef struct entryKeys {
    char *content; 
    size_t content_length;  // length of the entry_value
} entryKey;

typedef struct entryValues {
    char *message; 
    size_t message_length;  // length of the entry_value
} entryValue;

typedef std::pair<entryKey, entryValue> entry;

typedef struct Contents{
    char* content;
    int content_length;
} Content;

typedef struct
{
   uint32_t raw_bid; 

   uint32_t hash_bid;
   uint32_t counter; //re-encryption counter

   uint32_t path; //oram path 
   uint32_t index; //index 
   uint32_t bu; //bucket level
   uint32_t offset; //offset in the bucket

   uint32_t s; //destination location in the stash

} metaBlock;

//data structures used for ObliviousRangeReturn
typedef struct
{
    char tag1[ENTRY_HASH_KEY_LEN_128]; //this is the tag1
    char tag2[ENTRY_HASH_KEY_LEN_128]; //this is the tag2
    char k_part1[VIDEO_BLOCK_SIZE]; 
} metaRangeRet_p1;

typedef struct
{
    char tag2[ENTRY_HASH_KEY_LEN_128]; //this is the tag2
    char k_part2[VIDEO_BLOCK_SIZE]; 
    uint32_t s; //destination location in the stash
    int oramIndex;
} metaRangeRet_p2;

//data structure used for ObliviousBatchEvict
typedef struct
{
    char tag[ENTRY_HASH_KEY_LEN_128]; //this is the tag

    //FSS user key prg
    int key_arr[DPF_USER_KEY_PRG];
    unsigned int round;  

    //FSS key share
    uint8_t ks[DPF_PARTY_KEY];

    //re-encryption key
    char k_part[VIDEO_BLOCK_SIZE]; 
    
    int oramIndex; //oram index
    uint32_t bu; //bucket level
    uint32_t path; //oram path 
    uint32_t offset; //offset in the bucket

} metaOblivEvict;


//data structure used for OblivPerRe
typedef struct
{
    int originIndex; //this is the current old to query
    int newIndex; //move to this location
    char k_part[VIDEO_BLOCK_SIZE]; //re-encryption key

} metaPerRe;

//data structure used for PriRangeRet
typedef struct
{
    char tag[ENTRY_HASH_KEY_LEN_128]; //this is the tag if need to store in KeyShare and retrieve all following value from the (tag,value)

    //FSS user key prg
    int key_arr[DPF_USER_KEY_PRG];
    unsigned int round;

    //FSS key share
    uint8_t ks[DPF_PARTY_KEY];

    //re-encryption key
    char k_part[VIDEO_BLOCK_SIZE];

    int oramIndex; //oram index

    uint32_t path; //oram path

    uint32_t bu_from; //start to query blocks in (path,bu_from,offset) .... and inclusived (path,bu_max_inclusive,offset)

    uint32_t bu_max_inclusive;

    uint32_t offset; //offset in the bucket

    uint32_t stash_index;// after evaluate all, do re-encryption, and write to the stash_index of the Stash_r

} metaPriRangeRet;




//data structured used for routing map in untrusted server
typedef struct
{
    std::string ip;
    std::string port;
} network_entity; //used to export between ecall and ocall

typedef struct
{
    network_entity stash_network;
    network_entity edge_network;
} rORAMNetwork; 


#endif