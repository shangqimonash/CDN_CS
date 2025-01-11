#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
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
#include "EnclaveUtils.h"
#include <math.h>
#include "rORAM/rORAM.h"
#include "OblivRouting.h"

//change to malloc for tokens , run ulimit -s 65536 to set stack size to
//65536 KB in linux

// local variables inside Enclave
unsigned char masterK[ENC_KEY_SIZE] = {0};

PathORAM *video_map;
PathORAM *block_state;

//set the current R=32-> r in [0,6), largest range access = 2^5 blocks
int rORAM_num = 6; 
rORAM *rORAMTracker[6]; //rORAMTracker[i] includes the stash_r and BlockTracker_r

OblivRouting *routingUtil;


/*** setup */
void ecall_initial(int oram_video_map_bytes, int oram_block_state_bytes, int roram_tracker_bytes){

    //init master key
    sgx_read_rand(masterK, ENC_KEY_SIZE);

    //init the routing Utility
    routingUtil = new OblivRouting();

    // initialise the video map oram
    int num_of_bucket = oram_video_map_bytes / ORAM_DATA_SIZE / ORAM_BUCKET_SIZE;
    int oram_depth = ceil(log2(num_of_bucket)) - 1; //
    video_map = new PathORAM(oram_depth, ORAM_BUCKET_SIZE, ORAM_DATA_SIZE);
    video_map->clear();
    printf("\tvideo_map depth-%d, memory-%d: %.6lfMB\n", oram_depth, oram_video_map_bytes / 1024 / 1024.0);

    // initialise the block state oram
    num_of_bucket = oram_block_state_bytes / ORAM_DATA_SIZE / ORAM_BUCKET_SIZE;
    oram_depth = ceil(log2(num_of_bucket)) - 1; //
    block_state = new PathORAM(oram_depth, ORAM_BUCKET_SIZE, ORAM_DATA_SIZE);
    block_state->clear();
    printf("\tblock_state depth-%d, memory-%d: %.6lfMB\n", oram_depth, oram_block_state_bytes / 1024 / 1024.0);

   //initialise the roram, each contains stash_r and blockTracker_r
    for(int r = 0 ; r < rORAM_num; r++){
        num_of_bucket = roram_tracker_bytes / ORAM_BLOCK_KEY_SIZE / ORAM_BUCKET_SIZE;
        oram_depth = ceil(log2(num_of_bucket)) - 1; //
        rORAMTracker[r] = new rORAM(oram_depth, ORAM_BUCKET_SIZE, r, pow(2,r));
        rORAMTracker[r]->clear();
        printf("\n\tblock_tracker %d -> memory: %.6lfMB\n", r, roram_tracker_bytes / 1024 / 1024.0);
        printf("\tstash %d -> memory: %.6lfKB\n", r, (rORAMTracker[r]->getStashSize()* sizeof(uint32_t)) / 1024.0);

        //call outside to init the rORAM (Edge and Stash Servers)
        ocall_init_rORAM_Stash(r, rORAMTracker[r]->getStashSize(), rORAMTracker[r]->getRangeSize());
    }

}


void sync(int r,
            metaRangeRet_p1 *obliv_ret_metaReturn_p1, metaRangeRet_p2 *obliv_ret_metaReturn_p2, 
            blockPos *obliv_ret_edge_request,
            metaOblivEvict *obliv_batch_evict_p1,
            metaOblivEvict *obliv_batch_evict_p2){
    
    //the function triggers eviction in the logical rRAM and remotely trigger the physical rORAM outside
    printf("Execute syncORAM(%d)\n",r);

    //retrieve the metadata of blocks in the scheduled eviction paths in rORAMTracker[r]
    //in particular, the metadata includes the hash_bid, offset, path (% (2^i)), bu, index-noting that index does not include the stash size in default
    vector<metaBlock> blocks_on_paths = rORAMTracker[r]->retrieveBlocksOnEvictedPaths();

    //retrieve actual  the (counter, path, raw_bid) of the block from blockState (dummy block included)
    for(metaBlock b: blocks_on_paths){
        if(b.hash_bid !=0xFFFFFFFF){
                uint8_t bid_value[ORAM_DATA_SIZE];

                //read the current state for the hash_bid in block_state
                block_state->read((int)b.hash_bid, bid_value);

                b.counter = u8_to_u32(bid_value);
                b.path =  u8_to_u32(&bid_value[4]); //original path
                //b.index =  u8_to_u32(&bid_value[8]);   not in used used as OblivRangeRet relies on the secret sharing of bu,offset, and path
                b.raw_bid = u8_to_u32(&bid_value[12]); 

        }else{ //dummy block in that path
            sgx_read_rand((unsigned char *) &b.counter, 4);
            sgx_read_rand((unsigned char *) &b.raw_bid, 4); 
        }
    }
   
    //execute oblivRangeRet and update block_state
    routingUtil->oblivRangeRet(r, masterK, rORAMTracker[r],blocks_on_paths,block_state,
                            obliv_ret_metaReturn_p1, obliv_ret_metaReturn_p2,
                            obliv_ret_edge_request);

    //given *block state to the rORAMtracker to logically perform eviction in the ORAMTracker, return the metaBlock that are updated from Stash to rORAM
    vector<metaBlock> updated_blocks_eviction_paths  = rORAMTracker[r]->logicalEvictionFromStash(block_state);

    //execute OblivBatchEvict() and update block_state
    routingUtil->oblivBatchEvict(r, masterK, updated_blocks_eviction_paths, block_state,
                            obliv_batch_evict_p1, obliv_batch_evict_p2);

}

/*** set a video Length*/
void ecall_uploadVideoLength(int vId,int videoRangeLength){

    //set possible list of bid in the video, {bid=2^0,..., bid=2^15}, if so 1111111111111111
    //looping to create buffer, and mark byte at xth with flag=1 if support for that 2^xth range
    uint8_t v_range_value[ORAM_DATA_SIZE]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
     
    for(int i=0; i < videoRangeLength; i++){ //this movie length is 2^5-1 blocks: sample 11111000000000000 
        v_range_value[i] = (uint8_t)1;
    }

    //upload the videomap with Length
    video_map->write(vId,v_range_value);

}

/*** upload a video in a given range r*/
void ecall_uploadVideoInRange(int current_video_id, int r, 
                            char *content ,int content_length,
                            void *_obliv_ret_metaReturn_p1,
                            void *_obliv_ret_metaReturn_p2,
                            void *_obliv_ret_edge_request,
                            void *_obliv_batch_evict_p1,
                            void *_obliv_batch_evict_p2){

    //init casting the shared memory between utnrusted and trusted enclave
    metaRangeRet_p1 *obliv_ret_metaReturn_p1 = (metaRangeRet_p1*)_obliv_ret_metaReturn_p1;
    metaRangeRet_p2 *obliv_ret_metaReturn_p2 = (metaRangeRet_p2*)_obliv_ret_metaReturn_p2;
    blockPos *obliv_ret_edge_request = (blockPos*)_obliv_ret_edge_request;

    metaOblivEvict *obliv_batch_evict_p1 = (metaOblivEvict*)_obliv_batch_evict_p1;
    metaOblivEvict *obliv_batch_evict_p2 = (metaOblivEvict*)_obliv_batch_evict_p2;    


    //process blocks in this  range r
    printf("---> r: %d -----------\n",r);
    //start bid
    int bid_start = (int)pow(2,r);
               
    //declare metaBblocks with the size of the range r;
    metaBlock mBlocks[bid_start];  

    //declare final meta_enc_blocks with size of r to be sent outside for routing
    meta_enc_block m_e_Blocks[VIDEO_UPLOAD_EDGE_BATCH_SIZE];

    //declare temp plaintext block extracted from original content array
    char tmp_block_content[VIDEO_BLOCK_SIZE];

    //gen hash_bid for each block based on current H(video id, bid_i) % #blocks in BlockState
    for(int id_offset = 0; id_offset < bid_start; id_offset++){
        uint32_t hash_bid = genHashBlockId(std::to_string(bid_start+id_offset), current_video_id, block_state->get_block_count());
        mBlocks[id_offset].hash_bid = hash_bid;
    }

    //identify the meta data (path++, location in the stash) for blocks in mBlocks based on rORAMTracker[r]
    rORAMTracker[r]->stashUpload(mBlocks,bid_start);

    //for each block in the range, update the meta data for blocks in block_state oram, and generate encrypted block
    int cur_batch_size = 0;

    for(int id_offset = 0 ; id_offset< bid_start; id_offset++){

        uint8_t bid_value[ORAM_DATA_SIZE]; //16 bytes in format [counter,path,index, real bid_i of this block in this movie]

        //read the current state for the hash_bid in block_state
        block_state->read((int)mBlocks[id_offset].hash_bid, bid_value);

        //init counter, path and index already updated by stashUpload above
        uint32_t counter=0;

        //re-update in the value
        u32_to_u8(counter,bid_value);
        u32_to_u8(mBlocks[id_offset].path,&bid_value[4]);
        u32_to_u8(mBlocks[id_offset].index,&bid_value[8]);
        u32_to_u8(bid_start+id_offset,&bid_value[12]); //store the real int(bid_i) in the block state for later retrieve       

        //update BlockState_r for this block
        block_state->write(mBlocks[id_offset].hash_bid, bid_value);

        //keep track for batch outsourcing
        int batch_index = id_offset % VIDEO_UPLOAD_EDGE_BATCH_SIZE;
        m_e_Blocks[batch_index].bu = 0;
        m_e_Blocks[batch_index].path = mBlocks[id_offset].path;
        m_e_Blocks[batch_index].offset = mBlocks[id_offset].index;


        //extract the current block at id_offset in the char array content (see Maiden)
        memcpy(&tmp_block_content,content + (id_offset * VIDEO_BLOCK_SIZE),VIDEO_BLOCK_SIZE);
        //printf("Block indx %d, content: %.*s\n",id_offset,VIDEO_BLOCK_SIZE,tmp_block_content);
        
        //generate key to encrypt the current block, where k_1=F(masterK,bid_i||r||1)
        std::string m_key = std::to_string(bid_start+id_offset) + std::to_string(r) + std::to_string(1); //std::to_string(current_video_id) + 
        block_enc_xor_counter(masterK, m_key, counter, tmp_block_content, m_e_Blocks[batch_index].enc_content);

        cur_batch_size++;

        if(cur_batch_size == VIDEO_UPLOAD_EDGE_BATCH_SIZE){
            //instruct data to route the current batch to outside
            ocall_Stash_upload(m_e_Blocks,cur_batch_size,sizeof(meta_enc_block),r);
            //reset batch size
            cur_batch_size=0;
        }
    }

    //instruct data for routing the last batch to outside 
    if(cur_batch_size>0){
        ocall_Stash_upload(m_e_Blocks,cur_batch_size,sizeof(meta_enc_block),r);
    }

    //trigger the eviction
    sync(r,
        obliv_ret_metaReturn_p1,obliv_ret_metaReturn_p2,
        obliv_ret_edge_request,
        obliv_batch_evict_p1,
        obliv_batch_evict_p2);
}

void ecall_fetchVideo(int vId,
                      void *_per_re_p1, void *_per_re_p2,
                      void * _pri_range_ret_p1, void *_pri_range_ret_p2){
    //need to add param input for the sync later


    //init casting the shared memory between utnrusted and trusted enclave
    metaPerRe *per_re_p1 = (metaPerRe*)_per_re_p1;
    metaPerRe *per_re_p2 = (metaPerRe*)_per_re_p2;

    metaPriRangeRet * pri_range_ret_p1 =  (metaPriRangeRet *) _pri_range_ret_p1;
    metaPriRangeRet * pri_range_ret_p2 =  (metaPriRangeRet *) _pri_range_ret_p2;


    //int vId = 1;
    uint8_t range_video[ORAM_DATA_SIZE];
    video_map->read(vId,range_video);
    //print_bytes(range_value2,ORAM_DATA_SIZE);


    std::string str_id  = std::to_string(vId);

      //process blocks in each above range
    for(int r=0; r < ORAM_DATA_SIZE; r++){

        if(range_video[r]==(uint8_t)1){ //if the movie has the blocks in the range r

            printf("\n---> r: %d -----------\n",r);
            //start bid
            int bid_start = (int)pow(2,r); //range size
    

            //execute OblivPerRe to permute and re-encrypt all blocks in the stash (i.e., all blocks in stash have bu=0)
            routingUtil->OblivPerRe(r, masterK, rORAMTracker[r],block_state,
                                    per_re_p1, per_re_p2);

            //declare metaBblocks with the size of the range;
            metaBlock mBlocks[bid_start];  

            //then query the 2^r oram paths from blockTracker to the stash (logically) by using stashUpload (always 2^r blocks moving to the stash), call PriRangeRet
            //storage outside needs to keep the index PLUS by the stash

            for(int id_offset = 0; id_offset < bid_start; id_offset++)
            {
                uint32_t hash_bid = genHashBlockId(std::to_string(bid_start+id_offset), vId, block_state->get_block_count());
                mBlocks[id_offset].hash_bid = hash_bid;


                uint8_t bid_value[ORAM_DATA_SIZE];
                block_state->read((int)hash_bid, bid_value);

                //extract the value [c,l,index]
                mBlocks[id_offset].counter = u8_to_u32(bid_value);
                mBlocks[id_offset].path =  u8_to_u32(&bid_value[4]);
                mBlocks[id_offset].index =  u8_to_u32(&bid_value[8]);
                mBlocks[id_offset].raw_bid =  u8_to_u32(&bid_value[12]);

                uint32_t rORAM_r_stashSize = rORAMTracker[r]->getStashSize();


                mBlocks[id_offset].bu = ((mBlocks[id_offset].index- rORAM_r_stashSize) / ORAM_BUCKET_SIZE) + 1; //this is autocast to unsigned int, i.e., 1.2f = 1
                mBlocks[id_offset].offset = (mBlocks[id_offset].index  - rORAM_r_stashSize) % ORAM_BUCKET_SIZE;

                //if in the stash, obliviously update if the block is in the stash,  updating the bu = 0, ,and offset to be the index s_i found in the stash
                rORAMTracker[r]->blockInStash(&mBlocks[id_offset]);

                uint32_t bid_prime = mBlocks[id_offset].hash_bid;

                if(mBlocks[id_offset].bu ==0){ //if this block is already in the stash
                    bid_prime  = 0xFFFFFFFF; //asign dummy, this could be done in the above blockInStash function as well if needed
                }

                //convert offset to be always absolute so that dummy blocks still have positive offsets to query from oram outside
                mBlocks[id_offset].offset = abs((int)mBlocks[id_offset].index  - (int)rORAM_r_stashSize) % ORAM_BUCKET_SIZE;

                //update this block into the stash and retrieve the new location  s_i
                //if the block is already in the stash, it just inserts a dummy- not affect
                mBlocks[id_offset].s = rORAMTracker[r]->insertStash_OneBlock(bid_prime);

            }

            //execute PriRangeRet to route 2^r blocks back, if block already in the stash, i.e., (bu=0), gene dummy fss keys and re-encrytion keys
            routingUtil->PriRangeRet(r, masterK, rORAMTracker[r],block_state,
                                    mBlocks, bid_start, rORAMTracker[r]->getStashSize(),
                                    pri_range_ret_p1, pri_range_ret_p2);


            //execute the Sync()
        }
    }

}



void ecall_reset(){

    video_map->clear();
    delete video_map;

    block_state->clear();
    delete block_state;

    for(int r = 0 ; r < rORAM_num; r++){
        rORAMTracker[r]->clear();
        delete rORAMTracker[r];
    }


    delete routingUtil;
}


/*** no need as the first PerRe do not need this metaBlocks.
 * this block of code can be appended to the Fetch for testing
            for(int id_offset = 0; id_offset < bid_start; id_offset++)
            {
                uint32_t hash_bid = genHashBlockId(std::to_string(bid_start+id_offset), vId, block_state->get_block_count());
                mBlocks[id_offset].hash_bid = hash_bid;


                uint8_t bid_value[ORAM_DATA_SIZE];
                block_state->read((int)hash_bid, bid_value);

                //extract the value [c,l,index]
                mBlocks[id_offset].counter = u8_to_u32(bid_value);
                mBlocks[id_offset].path =  u8_to_u32(&bid_value[4]);
                mBlocks[id_offset].index =  u8_to_u32(&bid_value[8]);
                mBlocks[id_offset].raw_bid =  u8_to_u32(&bid_value[12]);            

                uint32_t rORAM_r_stashSize = rORAMTracker[r]->getStashSize();


                mBlocks[id_offset].bu = ((mBlocks[id_offset].index- rORAM_r_stashSize) / ORAM_BUCKET_SIZE) + 1;
                mBlocks[id_offset].offset = (mBlocks[id_offset].index  - rORAM_r_stashSize) % ORAM_BUCKET_SIZE;

                //printf("ORAM r stash size %d, bucket size %d", rORAM_r_stashSize,ORAM_BUCKET_SIZE);
                //printf("before stash check: index %d", (int)mBlocks[id_offset].index);     
                //printf("before stash check: bu %d", (int)mBlocks[id_offset].bu);
                //printf("before stash check: offset %d", (int)mBlocks[id_offset].offset);

                //obliviously update if the block is in the stash
                //if in the stash, will update the bu = 0, ,and offset to be the index s_i found in the stash
                rORAMTracker[r]->blockInStash(&mBlocks[id_offset]);

                //IMPORTANT FOR DEBUGGING
                //printf(">retest bid %d", (int) mBlocks[id_offset].hash_bid);
                //printf("retest counter %d", (int) mBlocks[id_offset].counter);
                //printf("retest path %d", (int)mBlocks[id_offset].path);
                //printf("retest index %d", (int)mBlocks[id_offset].index);                
                //printf("retest bu %d", (int)mBlocks[id_offset].bu);
                //printf("retest offset %d", (int)mBlocks[id_offset].offset);

            }

            //re-test to see, given the metaBlock (bu,path,offset) do we query correct the blockBID?, passed.
            //vector<metaBlock> test_result = rORAMTracker[r]->readRange(mBlocks,bid_start);


            ***/
