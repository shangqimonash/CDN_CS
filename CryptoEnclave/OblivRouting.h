#ifndef ENCLAVE_ROUTING_H
#define ENCLAVE_ROUTING_H

#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <map>
#include <algorithm>
#include <iterator>
#include <vector>
#include <list>
#include "../common/data_type.h"
#include "ORAM/PathORAM.h"
#include "rORAM/rORAM.h"
#include "EnclaveUtils.h"
#include <math.h>


using namespace std;

class OblivRouting {
public:

    void oblivRangeRet(const int treeIndex, const unsigned char * masterK, rORAM *current_rORAM, vector<metaBlock> &blocks_on_paths, PathORAM *block_state,
                       metaRangeRet_p1 *obliv_ret_metaReturn_p1, metaRangeRet_p2 *obliv_ret_metaReturn_p2,
                       blockPos *obliv_ret_edge_request)
    {
        //printf("Tree index %d, #blocks to return to stash %d\n",treeIndex, blocks_on_paths.size());

        //create random salt to add to the tag K2 generation
        uint32_t randFactor;

        //step 1. move blocks_on_paths to the stash_r and updates each block in blocks_on_paths with the location s in the stash
        current_rORAM->oblivStashInsert(blocks_on_paths);

        //declare temp keys (equal block size) used for old counter and a newly (c+1)
        char k_enc_temp_old_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_new_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_key[VIDEO_BLOCK_SIZE]; // this is k^prime_i, being xored of above two keys

        int batch_index = 0;

        //step 2. gen key based on the current counter c, and a newly (c+1) to ask network routing move from (r,l,bu,o) into the stash at the destination location s
        for(metaBlock b: blocks_on_paths){

            //generate key to encrypt the current block, where k_1=F(masterK,bid_i||r||1)
            std::string m_key = std::to_string(b.raw_bid) + std::to_string(treeIndex) + std::to_string(1); //std::to_string(current_video_id)

            //declare the temp of K_1 and K_2
            entryKey k_1, k_2;

            //generate the key for re-encryption block, to be saved in k_enc_temp_key
            k_1.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + m_key.size();
            k_1.content = (char *) malloc(k_1.content_length);
            enc_aes_gcm(masterK,m_key.c_str(),m_key.size(),k_1.content,k_1.content_length);

            hash_SHA_BlockSize(k_1.content,b.counter,k_enc_temp_old_counter);
            hash_SHA_BlockSize(k_1.content,b.counter + 1,k_enc_temp_new_counter);

            for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                k_enc_temp_key[byte_index] = (char) (k_enc_temp_old_counter[byte_index] ^ k_enc_temp_new_counter[byte_index]);
            }

            free(k_1.content);

            //random generate the key k_part1
            sgx_read_rand((unsigned char*)obliv_ret_metaReturn_p1[batch_index].k_part1, VIDEO_BLOCK_SIZE);

            //xoring to get the key of k_part2
            for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                obliv_ret_metaReturn_p2[batch_index].k_part2[byte_index] = (char) (k_enc_temp_key[byte_index] ^ obliv_ret_metaReturn_p1[batch_index].k_part1[byte_index]);
            }

            //generate the key k_2 for the tag generation
            sgx_read_rand((unsigned char *) &randFactor, 4);

            m_key = std::to_string(b.raw_bid) + std::to_string(treeIndex) + std::to_string(2) + std::to_string(randFactor);
            k_2.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + m_key.size();
            k_2.content = (char *) malloc(k_2.content_length);
            enc_aes_gcm(masterK,m_key.c_str(),m_key.size(),k_2.content,k_2.content_length);

            //update tag1 and tag2 for obliv_ret_metaReturn_p1[batch_index]
            tag_gen_key_counter(k_2.content,b.counter + 1,obliv_ret_metaReturn_p1[batch_index].tag1,obliv_ret_metaReturn_p1[batch_index].tag2);

            //memcpy to tag2 for obliv_ret_metaReturn_p2[batch_index]
            memcpy(obliv_ret_metaReturn_p2[batch_index].tag2,obliv_ret_metaReturn_p1[batch_index].tag2,ENTRY_HASH_KEY_LEN_128);

            //update the index s in the stash and the oram index r
            obliv_ret_metaReturn_p2[batch_index].s = b.s;
            obliv_ret_metaReturn_p2[batch_index].oramIndex = treeIndex;


            free(k_2.content);

            //update obliv_ret_edge_request[batch_index] to later send to Edge Sever_r
            obliv_ret_edge_request[batch_index].path = b.path;
            obliv_ret_edge_request[batch_index].bu = b.bu;
            obliv_ret_edge_request[batch_index].offset = b.offset;

            batch_index++;

            if(batch_index == OBLIV_RETURN_BATCH_SIZE) {
                //perform ocall for batching with size for sharing
                ocall_oblivRet( treeIndex, batch_index);

                //reset the batch
                batch_index = 0;
            }
        }

        if(batch_index > 0){

            //perform ocall for batching with size
            ocall_oblivRet(treeIndex, batch_index);

            //reset the batch
            batch_index = 0;
        }

        //update the counter value of (c+1) and the location s of this block in the blockstate to be the index
        for(metaBlock b: blocks_on_paths){
            if(b.hash_bid !=0xFFFFFFFF){

                uint8_t bid_value[ORAM_DATA_SIZE];

                b.counter = (int)b.counter+1;
                //printf(">bid %d", (int)b.hash_bid);
                //printf("counter %d", (int)b.counter);

                //re-update in the value
                u32_to_u8(b.counter,bid_value);
                u32_to_u8(b.path,&bid_value[4]); //no need to unchange the path as we query them back to the stash
                u32_to_u8(b.s,&bid_value[8]); //update the new position in the Stash
                u32_to_u8(b.raw_bid,&bid_value[12]);

                //update BlockState_r for this block
                block_state->write(b.hash_bid, bid_value);
            }else{
                //dummy access to the blockState
            }
        }
    }


    void oblivBatchEvict(const int treeIndex, const unsigned char * masterK, vector<metaBlock> &evicted_blocks, PathORAM *block_state,
                         metaOblivEvict *obliv_batch_evict_p1,
                         metaOblivEvict *obliv_batch_evict_p2){

        //declare temp keys (equal block size) used for old counter and a newly (c+1)
        char k_enc_temp_old_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_new_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_key[VIDEO_BLOCK_SIZE]; // this is k^prime_i, being xored of above two keys

        int batch_index = 0;

        //create random salt to add to the tag K2 generation
        uint32_t randFactor;

        //OBLIV_BATCH_EVICT_SIZE

        //step 1. gen key based on the current counter c, and a newly (c+1) to ask network routing move from (r,l,bu,o) into the stash at the destination location s
        for(metaBlock b: evicted_blocks){

            //generate key to encrypt the current block, where k_1=F(masterK,bid_i||r||1)
            std::string m_key = std::to_string(b.raw_bid) + std::to_string(treeIndex) + std::to_string(1); //std::to_string(current_video_id)

            //declare the temp of K_1 and K_2
            entryKey k_1, k_2;


            //generate the key for re-encryption block, to be saved in k_enc_temp_key
            k_1.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + m_key.size();
            k_1.content = (char *) malloc(k_1.content_length);
            enc_aes_gcm(masterK,m_key.c_str(),m_key.size(),k_1.content,k_1.content_length);

            hash_SHA_BlockSize(k_1.content,b.counter,k_enc_temp_old_counter);
            hash_SHA_BlockSize(k_1.content,b.counter + 1,k_enc_temp_new_counter);

            for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                k_enc_temp_key[byte_index] = (char) (k_enc_temp_old_counter[byte_index] ^ k_enc_temp_new_counter[byte_index]);
            }

            free(k_1.content);

            //random generate the key k_part1
            sgx_read_rand((unsigned char*)obliv_batch_evict_p1[batch_index].k_part, VIDEO_BLOCK_SIZE);

            //xoring to get the key of k_part2
            for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                obliv_batch_evict_p2[batch_index].k_part[byte_index] = (char) (k_enc_temp_key[byte_index] ^ obliv_batch_evict_p1[batch_index].k_part[byte_index]);
            }

            //generate the key k_2 for the tag generation
            sgx_read_rand((unsigned char *) &randFactor, 4);

            m_key = std::to_string(b.raw_bid) + std::to_string(treeIndex) + std::to_string(2) + std::to_string(randFactor);
            k_2.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + m_key.size();
            k_2.content = (char *) malloc(k_2.content_length);
            enc_aes_gcm(masterK,m_key.c_str(),m_key.size(),k_2.content,k_2.content_length);

            //update tag1 and tag2 for obliv_batch_evict_p1[batch_index] and obliv_batch_evict_p2[batch_index]
            tag_gen_key_counter_oblivBatch(k_2.content,b.counter + 1,obliv_batch_evict_p1[batch_index].tag);

            //memcpy to tag2 for obliv_batch_evict_p2[batch_index]
            memcpy(obliv_batch_evict_p2[batch_index].tag,obliv_batch_evict_p1[batch_index].tag,ENTRY_HASH_KEY_LEN_128);


            free(k_2.content);

            //dpf_block_test(treeIndex, b.s);

            dpf_gen_serialise(treeIndex, b.s,obliv_batch_evict_p1[batch_index].key_arr,&obliv_batch_evict_p1[batch_index].round,
                              obliv_batch_evict_p1[batch_index].ks, obliv_batch_evict_p2[batch_index].ks);


            //copy to obliv_batch_evict_p2[batch_index].key_arr
            memcpy(obliv_batch_evict_p2[batch_index].key_arr,obliv_batch_evict_p1[batch_index].key_arr,DPF_USER_KEY_PRG);
            obliv_batch_evict_p2[batch_index].round = obliv_batch_evict_p1[batch_index].round;


            //dpf_deserialised_test(treeIndex, obliv_batch_evict_p1[batch_index].key_arr,obliv_batch_evict_p1[batch_index].round,obliv_batch_evict_p1[batch_index].ks,
            //                      b.s,
            //                     obliv_batch_evict_p2[batch_index].key_arr, obliv_batch_evict_p2[batch_index].round, obliv_batch_evict_p2[batch_index].ks);


            //update the index s in the stash and the oram index r, (moving from s to (l,bu,o));
            obliv_batch_evict_p1[batch_index].oramIndex = treeIndex;
            obliv_batch_evict_p2[batch_index].oramIndex = treeIndex;

            obliv_batch_evict_p1[batch_index].bu = b.bu;
            obliv_batch_evict_p2[batch_index].bu = b.bu;

            obliv_batch_evict_p1[batch_index].path = b.path;
            obliv_batch_evict_p2[batch_index].path = b.path;

            obliv_batch_evict_p1[batch_index].offset = b.offset;
            obliv_batch_evict_p2[batch_index].offset = b.offset;


            batch_index++;

            if(batch_index == OBLIV_BATCH_EVICT_SIZE) {
                //perform ocall for batching with size for sharing
                ocall_oblivEvict_pushCE( treeIndex, batch_index);

                //reset the batch
                batch_index = 0;
            }
            //batchIndex++ then =0
        }

        if(batch_index > 0){

            //perform ocall for batching with size
            ocall_oblivEvict_pushCE(treeIndex, batch_index);

            //reset the batch
            batch_index = 0;
        }



        //notify the Stash to send blocks to the CE
        ocall_oblivEvict_pushStash(treeIndex);

        //step2: update the blocks in evicted_blocks in blockState with the newly counter value (counter +1, path,index)
        for(metaBlock b: evicted_blocks){
            if(b.hash_bid !=0xFFFFFFFF){

                uint8_t bid_value[ORAM_DATA_SIZE];
                //printf("-------");
                //printf("evict bid %d", (int) b.hash_bid);
                //printf(">>evict counter before %d", (int) b.counter);
                b.counter=(int)b.counter+1;

                //re-update in the value
                u32_to_u8(b.counter,bid_value);
                u32_to_u8(b.path,&bid_value[4]); //no need to unchange the path
                u32_to_u8(b.index,&bid_value[8]);
                u32_to_u8(b.raw_bid,&bid_value[12]);

                //printf(">evict counter after %d", (int) b.counter);
                //printf("retest path %d", (int)b.path);
                //printf("retest bu %d",(int)b.bu);
                //printf("retest index %d", (int)b.index);

                //update BlockState_r for this block
                block_state->write(b.hash_bid, bid_value);

            }else{
                //dummy access to the blockState
            }
        }
    }

    void OblivPerRe(const int treeIndex, const unsigned char * masterK,rORAM *current_rORAM, PathORAM *block_state,
                    metaPerRe *per_re_p1,  metaPerRe *per_re_p2){

        //check the fixed-size array should be the same with the current size
        //printf("\Capacity of stash size  %d, current stash size %d, \n", current_rORAM->getStashSize(), current_rORAM->getCurrent_Stash_Size());


        //get the current size and init 2 permutation arrays
        uint32_t stash_size = current_rORAM->getStashSize();
        uint32_t *permute1 =  (uint32_t *) malloc(sizeof(uint32_t) * stash_size);
        uint32_t *permute2 =  (uint32_t *) malloc(sizeof(uint32_t) * stash_size);

        for(int j=0; j < stash_size; j++){
            permute1[j] = j; permute2[j] = j;
        }

        //create permute for the CEs
        permute(permute1,stash_size);
        permute(permute2,stash_size);

        //printf("\nPermute 1 \n");
        //for(int v=0; v< stash_size; v++){
        //    printf("%d,",permute1[v]);
        //}

        //printf("\nPermute 2 \n");
        //for(int v=0; v< stash_size; v++){
        //    printf("%d,",permute2[v]);
        //}

        //create uint32_t *arr to later rset the Stash
        uint32_t *new_stash_bids =  (uint32_t *) malloc(sizeof(uint32_t) * stash_size);

        //get immutable pointer of the Stash, to track new locations
        rNode *iter = current_rORAM->get_Stash_start();

        //gen for each block in the stash, new intermediate pos, and final pos
        uint32_t original_pos = 0;
        uint32_t intermediate_pos, final_pos = 0;

        //declare a temp block extracted from BlockState while scanning the stash
        metaBlock temp;
        uint8_t bid_value[ORAM_DATA_SIZE];

        //declare temp keys (equal block size) used for old counter and a newly (c+1)
        char k_enc_temp_old_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_new_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_key[VIDEO_BLOCK_SIZE]; // this is k^prime_i, being xored of above two keys

        while(iter != nullptr) {

            intermediate_pos = findIndexOfValue(permute1,stash_size,original_pos);
            final_pos = findIndexOfValue(permute2,stash_size,original_pos);

            new_stash_bids[final_pos] = iter->b.id;


            //update the per_re_p1 and per_re_p2
            per_re_p1[original_pos].originIndex = original_pos;
            per_re_p1[original_pos].newIndex = intermediate_pos;

            per_re_p2[original_pos].originIndex = intermediate_pos;
            per_re_p2[original_pos].newIndex = final_pos;

            //retrieve the BlockState to get key-share, and re-update new counter, and new location s_i
            if(iter->b.id != 0xFFFFFFFF) {
                block_state->read((int)iter->b.id , bid_value);
                temp.counter =  u8_to_u32(bid_value); //extract the counter
                temp.path =  u8_to_u32(&bid_value[4]); //extract path
                temp.index =  u8_to_u32(&bid_value[8]); //extract current index
                temp.raw_bid = u8_to_u32(&bid_value[12]); ////extract the raw_id



                //generate key to encrypt the current block, where k_1=F(masterK,bid_i||r||1)
                std::string m_key = std::to_string(temp.raw_bid) + std::to_string(treeIndex) + std::to_string(1); //std::to_string(current_video_id)
                //declare the temp k_1;
                entryKey k_1;

                //generate the key for re-encryption block, to be saved in k_enc_temp_key
                k_1.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + m_key.size();
                k_1.content = (char *) malloc(k_1.content_length);
                enc_aes_gcm(masterK,m_key.c_str(),m_key.size(),k_1.content,k_1.content_length);

                hash_SHA_BlockSize(k_1.content,temp.counter,k_enc_temp_old_counter);
                hash_SHA_BlockSize(k_1.content,temp.counter + 1,k_enc_temp_new_counter);

                //update k_enc_temp_key
                for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                    k_enc_temp_key[byte_index] = (char) (k_enc_temp_old_counter[byte_index] ^ k_enc_temp_new_counter[byte_index]);
                }

                //free content of k_1
                free(k_1.content);

                //random generate the key per_re_p1[original_pos].k_part
                sgx_read_rand((unsigned char*)per_re_p1[original_pos].k_part, VIDEO_BLOCK_SIZE);

                //xoring to get the key of k_part2
                for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                    per_re_p2[original_pos].k_part [byte_index] = (char) (k_enc_temp_key[byte_index] ^ per_re_p1[original_pos].k_part[byte_index]);
                }

                //update the tempblock( with counter+1, and new index=final_pos) to bid_value
                temp.counter +=1;
                temp.index = final_pos;

                //re-update the blockState of this temp block
                //cast to bid_value array
                u32_to_u8(temp.counter,bid_value);
                u32_to_u8(temp.path,&bid_value[4]); //no need to unchange the path
                u32_to_u8(temp.index,&bid_value[8]);
                u32_to_u8(temp.raw_bid,&bid_value[12]);

                //update BlockState_r for this block
                block_state->write((int)iter->b.id, bid_value);

            } else{
                //dummy access to BlockState the ncreate dummy key shares
                //random generate the key per_re_p1[original_pos].k_part
                sgx_read_rand((unsigned char*)per_re_p1[original_pos].k_part, VIDEO_BLOCK_SIZE);
                sgx_read_rand((unsigned char*)per_re_p2[original_pos].k_part, VIDEO_BLOCK_SIZE);
            }

            //move to the next element in the Stash
            iter = iter->prev;

            //increase the counter original_pos
            original_pos++;
        }

        //reset the meta stash of this rORAM with new array of BiD
        current_rORAM->reset_stash_newIds(new_stash_bids,stash_size);

        //free temp daa
        free(new_stash_bids);
        free(permute1);
        free (permute2);


        //call to the api once time only, also give the stash size
        ocall_oblivPerRe(treeIndex, stash_size);

    }


    void  PriRangeRet(const int treeIndex, const unsigned char * masterK,rORAM *current_rORAM, PathORAM *block_state,
                      metaBlock *mBlocks, int rangeSize, uint32_t starting_index,
                      metaPriRangeRet * pri_range_ret_p1, metaPriRangeRet * pri_range_ret_p2 ) {


        //declare temp keys (equal block size) used for old counter and a newly (c+1)
        char k_enc_temp_old_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_new_counter[VIDEO_BLOCK_SIZE];
        char k_enc_temp_key[VIDEO_BLOCK_SIZE]; // this is k^prime_i, being xored of above two keys

        //create random salt to add to the tag K2 generation
        uint32_t randFactor;

        //select a new random path to assign
        int starting_random_path = current_rORAM->retrieve_random_path();        //retrieve the first random path one from the tree T_r

        for(int batch_index = 0; batch_index < rangeSize; batch_index++){

            //retrieve the current metablock b from the batch index
            metaBlock b = mBlocks[batch_index];

            //[step 1. gen re-encryption key and share to two ce1 ce2]

            //generate key to encrypt the current block, where k_1=F(masterK,bid_i||r||1)
            std::string m_key = std::to_string(b.raw_bid) + std::to_string(treeIndex) + std::to_string(1); //std::to_string(current_video_id)

            //declare the temp of K_1 and K_2
            entryKey k_1, k_2;

            //generate the key for re-encryption block, to be saved in k_enc_temp_key
            k_1.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + m_key.size();
            k_1.content = (char *) malloc(k_1.content_length);
            enc_aes_gcm(masterK,m_key.c_str(),m_key.size(),k_1.content,k_1.content_length);

            hash_SHA_BlockSize(k_1.content,b.counter,k_enc_temp_old_counter);
            hash_SHA_BlockSize(k_1.content,b.counter + 1,k_enc_temp_new_counter);

            for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                k_enc_temp_key[byte_index] = (char) (k_enc_temp_old_counter[byte_index] ^ k_enc_temp_new_counter[byte_index]);
            }

            free(k_1.content);

            //random generate the re-encryption key k_part1
            sgx_read_rand((unsigned char*)pri_range_ret_p1[batch_index].k_part, VIDEO_BLOCK_SIZE);

            //xoring to get the key of k_part2
            for(int byte_index = 0 ; byte_index < VIDEO_BLOCK_SIZE; byte_index++){
                pri_range_ret_p2[batch_index].k_part[byte_index] = (char) (k_enc_temp_key[byte_index] ^ pri_range_ret_p1[batch_index].k_part[byte_index]);
            }


            //[step 2. gen the tag and share the same tag to two ce1 ce2] by using  the key k_2
            sgx_read_rand((unsigned char *) &randFactor, 4);

            m_key = std::to_string(b.raw_bid) + std::to_string(treeIndex) + std::to_string(2) + std::to_string(randFactor);
            k_2.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + m_key.size();
            k_2.content = (char *) malloc(k_2.content_length);
            enc_aes_gcm(masterK,m_key.c_str(),m_key.size(),k_2.content,k_2.content_length);

            //update tag1 and tag2 for pri_range_ret_p1[batch_index] and pri_range_ret_p2[batch_index]
            tag_gen_key_counter_oblivBatch(k_2.content,b.counter + 1,pri_range_ret_p1[batch_index].tag);

            //memcpy to tag2 for obliv_batch_evict_p2[batch_index]
            memcpy(pri_range_ret_p2[batch_index].tag,pri_range_ret_p1[batch_index].tag,ENTRY_HASH_KEY_LEN_128);

            free(k_2.content);

            //[step 3. gen the FSS key shares based on the index, each key share contains (key_arr for prg, round, FSS key share)]
            dpf_gen_serialise(treeIndex, b.index,pri_range_ret_p1[batch_index].key_arr,&pri_range_ret_p1[batch_index].round,
                              pri_range_ret_p1[batch_index].ks, pri_range_ret_p2[batch_index].ks);


            //copy to pri_range_ret_p2[batch_index].key_arr of PRG and round
            memcpy(pri_range_ret_p2[batch_index].key_arr,pri_range_ret_p1[batch_index].key_arr,DPF_USER_KEY_PRG);
            pri_range_ret_p2[batch_index].round = pri_range_ret_p1[batch_index].round;

            //[step 4. update meta addresses of blocks that need to be queried for evaluation]

            //update tree index
            pri_range_ret_p1[batch_index].oramIndex = treeIndex;
            pri_range_ret_p2[batch_index].oramIndex = treeIndex;

            //update current oram path
            pri_range_ret_p1[batch_index].path = b.path;
            pri_range_ret_p2[batch_index].path = b.path;

            //update the current offset
            pri_range_ret_p1[batch_index].offset = b.offset;
            pri_range_ret_p2[batch_index].offset = b.offset;

            //update the bu level from to queries from 1
            pri_range_ret_p1[batch_index].bu_from = 1; //partition e (aka bu) start from 1, because stash  has e (aka bu) = 0
            pri_range_ret_p2[batch_index].bu_from = 1;

            //update to query up to bu = depth +1;
            pri_range_ret_p1[batch_index].bu_max_inclusive = current_rORAM->retrieve_getDepth() + 1; //depth + 1 accordingly
            pri_range_ret_p2[batch_index].bu_max_inclusive = current_rORAM->retrieve_getDepth() + 1;


            //[step 5. update location where to route the final block after re-encrypted to the Stash]
            pri_range_ret_p1[batch_index].stash_index = b.s;
            pri_range_ret_p2[batch_index].stash_index = b.s;


            //[step 6. start to update this block state with new lexical order path]
            if(batch_index==0){
                b.path =  starting_random_path;
            }else{
                b.path = current_rORAM->retrieve_lexical_path_order(starting_random_path);
                starting_random_path++;
            }

            //if(bu!=0, update blockstate with new counter, this new location in the stasg s_i)
            //otherwise, update all for all blocks in mBlocks update each block with blockstate with new path+1

            uint8_t bid_value[ORAM_DATA_SIZE];
            if(b.bu !=0){
                b.counter = (int)b.counter+1;
                b.index = b.s; //update new location should be in the stash
                //if the block is already in the stash, the index of the block in the stash should be the same as b.index as retrieved from blockState
            }
            //re-update in the value
            u32_to_u8(b.counter,bid_value); //this is unchanged if block is in the stash
            u32_to_u8(b.path,&bid_value[4]);
            u32_to_u8(b.index,&bid_value[8]); //update the new position in the Stash
            u32_to_u8(b.raw_bid,&bid_value[12]);

            //update BlockState_r for this block
            block_state->write(b.hash_bid, bid_value);
        }

        //call to outside
        ocall_oblivPriRangeRetrieve(treeIndex, starting_index, rangeSize);

    }
};

#endif