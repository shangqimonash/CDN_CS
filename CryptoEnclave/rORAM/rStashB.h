#ifndef rORAM_STASH_H
#define rORAM_STASH_H


#include "../../common/config.h"

#include <string>
#include <map>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include "stdlib.h"
#include <cstring>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include "../../common/config.h"
#include "../EnclaveUtils.h"

#include "../ORAM/PathORAM.h"

struct __attribute__((packed)) rBlock {
    uint32_t id;
};

struct __attribute__((packed)) rBucket {
    rBlock ids[ORAM_BUCKET_SIZE];
};


struct __attribute__((packed)) rNode {
    rBlock b;
    rNode *prev;
    rNode *next;
};

class rStashB {
private:
    rNode *top;
    rNode *bottom;
    uint32_t stash_size;        // the upper bound of the stash size
    uint32_t current_size;

    int oramID;
public:
    rStashB( int _oramID, uint32_t size) {
        stash_size = size;
        current_size = 0;

        top = nullptr;
        bottom = nullptr;

        oramID = _oramID;

        //init dummy to fit all the size
        uint32_t bid = 0xFFFFFFFF;
        for (int i=0; i < stash_size; i++) {
            rBlock new_block;
            new_block.id = bid;
            forceInsertDummy(new_block);
        }

        //printf("Stash current size %d\n",current_size);
    }

    ~rStashB() {
        clear();
    }

    void clear() {
        rNode *iter = get_start();
        while(iter != nullptr) {
            rNode *cur = iter;
            iter = iter->prev;
            free(cur);
        }

        top = nullptr;
        bottom = nullptr;

        //IMPORTANT TO RESET
        current_size = 0;

        //init dummy to fit all the size
        uint32_t bid = 0xFFFFFFFF;
        for (int i=0; i < stash_size; i++) {
            rBlock new_block;
            new_block.id = bid;
            forceInsertDummy(new_block);
        }

    }

    rNode* get_start() const {
        return top;
    }

    void forceInsertDummy(rBlock &new_block){

        // insert the new node since it does not exist
        rNode *new_node = (rNode*) malloc(sizeof(rNode));
       
        // reset the pointer
        new_node->prev = nullptr;
        new_node->next = nullptr;

        // attach at the end of the stash
        if(current_size > stash_size) {
            printf(">>Stash %d: overflowed, current size %d", oramID,current_size);
            return ;     // stash is full, ignore this block
        } else {
            
            memcpy(&new_node->b, &new_block, sizeof(rBlock));
            
            if(bottom == nullptr) {     // empty stash
                bottom = new_node;
                top = new_node;
            } else {
                bottom->prev = new_node;
                new_node->next = bottom;
                bottom = new_node;
            }
            current_size++;
        }
    }

    int insert(rBlock &new_block) {
        // scan the stash to rewrite the existing blocks
        rNode *iter = get_start();

        int cur_index = -1;

        int last_dummy_index = -1;

        while(iter != nullptr) {
            cur_index+=1;
            if(0xFFFFFFFF == iter->b.id){
                last_dummy_index = cur_index;
            }

            iter = iter->prev;
        }


        // replace the last dummy bid=0xFFFFFFFF in the stash
        if(last_dummy_index == -1 ) {
            printf(">>Stash index %d: overflowed, current size %d", oramID,current_size);
            return -1;     // stash is full, ignore this block
        } else {

            iter = get_start();
            cur_index = -1;
            while(iter != nullptr) {
                cur_index+=1;
                if(cur_index == last_dummy_index){
                    iter->b.id = new_block.id;
                }
                iter = iter->prev;
            }
        }

        //return the current index where to store the block
        return last_dummy_index;
        
    }

    void forceResetStash(rBlock &new_block, int index){
        rNode *iter = get_start();
        int cur_index = -1;
        while(iter != nullptr) {
            cur_index+=1;
            if(cur_index == index){
                    iter->b.id = new_block.id;
            }
            iter = iter->prev;
        }
    }

    void erase(rNode *del_block) {
        rNode *iter = get_start();
        while(iter != nullptr) {
            if( del_block->b.id == iter->b.id){
                iter->b.id = 0xFFFFFFFF;
            }
            iter = iter->prev;
        }
    }

    int search(uint32_t bid) {
        if(top!=nullptr){
            if(top->b.id == bid){
                return 0; // at the top
            }
        }

        int found = 0;
        rNode *iter = top;
        while(iter != nullptr) {
            if(iter->b.id == bid) {
                return found;
            }
            iter = iter->prev;
            found++;
        }
        // not found return empty
        return -1;
    }

    //scan stash to later pool nodes used to against eviction schedule
    void scan( std::map<uint32_t, metaBlock> &m, PathORAM *block_state){
        
        rNode *iter = top;
        while(iter != nullptr) {
            if(iter->b.id != 0xFFFFFFFF) {

                metaBlock temp; 

                uint8_t bid_value[ORAM_DATA_SIZE];

                block_state->read((int)iter->b.id , bid_value);

                //extract the counter
                temp.counter =  u8_to_u32(bid_value);
                
                //extract path 
                temp.path =  u8_to_u32(&bid_value[4]);

                //extract the raw_id
                temp.raw_bid = u8_to_u32(&bid_value[12]);
                 
                m[iter->b.id] = temp;

            }
            iter = iter->prev;
            
        }
    }

    uint32_t getCurrentSize(){
        return current_size;
    }

    void printStash(){

        printf("\nPrint stash r %d\n", oramID);
        rNode *iter = get_start();
        if(iter == nullptr){
            printf("\nNull stash\n");
        }else {
            while(iter != nullptr) {
                printf("%d,",iter->b.id);
                iter = iter->prev;
            }
        }

        printf("\nEnd stash r %d\n", oramID);

    }
};

#endif