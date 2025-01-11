#ifndef rORAM_H
#define rORAM_H

#include <algorithm>
#include <cmath>
#include <unordered_map>
#include <vector>
#include "../common/data_type.h"
#include "../EnclaveUtils.h"
#include "rStashB.h"
#include "../common/oblivious-primitives.h"
#include <stdlib.h>
#include "../ORAM/PathORAM.h"
#include <map>
#include <stdlib.h>

using namespace std;

//bid dummy 0xFFFFFFFF;

class rORAM { //this tree only maintains the bid in the range
private:
    // basic settings
    uint32_t depth;         // the depth of the tree
    uint8_t Z;              // # of blocks per bucket
    uint32_t N;             // # of buckets in this ORAM
    uint32_t B;             // size of data;

    uint32_t leafNum;       // # of leaf buckets

    rBlock *store;           // a bucket list
    uint32_t *position;     // position map
    
    uint32_t stash_size; //stash size
    rStashB *stash;            // stash

    int oramID;             //oram id tree
    int rangeSize;          //range 2^r supported by this tree
    long evictCounter;      //eviction schedule
    
    // operators on the tree
    uint32_t random_path() {
        // assign a random path to the leaf
        // note that the leaf id is between [0, N/2]
        uint32_t rand;
        RAND_bytes((uint8_t*) &rand, sizeof(uint32_t));
        return rand % (N / 2);
    }

    int read_stash(int bid) { //return location in the stash or -1
        return stash->search(bid);
    }

    int write_stash(int bid) {
        rBlock new_block;
        new_block.id = bid;
        return stash->insert(new_block);
    }

    uint32_t get_random_path(){
        return random_path();
    }

    uint32_t get_lexical_path_order(uint32_t cur_path ){    
        return (cur_path+1) % (N / 2);
    }

    vector<metaBlock> batchReadPaths(int leafLabel,int rangeSize){

        int numberOfBuckets[depth+1];
        int bucketLabel[depth+1];

        for(int d=depth; d>=0; d--){
            if(d==0){
                bucketLabel[d]=0;
            }else{
                bucketLabel[d] = (leafLabel) % ((int) pow(2,d));
            }

            numberOfBuckets[d] = ((int)min((int) pow(2,d),rangeSize));
        }

        return downloadChunk(bucketLabel,numberOfBuckets);

    }

    vector<metaBlock> downloadChunk(int *startingBucket, int *numOfBuckets){
        
        vector<metaBlock> v;

        int bucketsUptoEnd[depth+1]; 
		int bucketsFromStart[depth+1]; 

        for(int i=depth; i >= 0; i--){
				bucketsUptoEnd[i] = 0;
				bucketsFromStart[i] = 0;
				int startingOffsetAtLevel; //this denotes the starting bucketId of each level

               /*  Identify wrap around for level based on numOfBuckets */
				if(i == 0) 
					startingOffsetAtLevel = 0;
				else 
					startingOffsetAtLevel = (int) (pow(2, i)-1); //identify real place of the first bucket at each level

			    int t = 0;
				while(t < numOfBuckets[i]) {
					if((startingBucket[i]+t) < ((int) (pow(2, i))))
						bucketsUptoEnd[i] += 1;
					else
						bucketsFromStart[i] += 1;
					t++;
				}

                int temp=0;
                int memoryOffset = (startingBucket[i]+startingOffsetAtLevel);
				int cntr = 0;

				/* Retrieve buckets up to end of the level starting from startBucket */
				while(temp < bucketsUptoEnd[i]) {
				    temp++;	
				    cntr++;
				}	

                int addressOffset = memoryOffset*Z;	
                int memoryReadSize = Z*cntr;
                int temp_path = startingBucket[i] % (int) pow(2,i); //????

                //read memory
                for (int j=addressOffset ; j < addressOffset + memoryReadSize ; j++){
                        metaBlock visited_block;
                        
                        //increase temp_path if needed based on lexical path order
                        if(j > addressOffset && (j % Z) == 0)
                            temp_path++;

                        visited_block.hash_bid = store[j].id;
                        visited_block.offset = j % Z;
                        visited_block.path = temp_path % (int) pow(2,i);
                        visited_block.index = (Z * i) + (j % Z);
                        visited_block.bu = i+1 ; //bu level

                        //add to the set v
                        v.push_back(visited_block);

                        //reset store[j]
                        store[j].id =  0xFFFFFFFF;
                        

                }	

                temp = 0;
                memoryOffset = startingOffsetAtLevel;
                cntr = 0;
                temp_path = 0; //starting from 0 again due to wrap and round.

                //when setting the path, increasing, also wrap and round by leafNum
        
                /* Retrieve buckets after wrap around from start of level */
                if(bucketsFromStart[i]>0){
                    while(temp < bucketsFromStart[i]){
                        temp++;
						cntr++;
                    }
                    
                }

                addressOffset = memoryOffset*Z;	
                memoryReadSize = Z*cntr;

                ///for debug
                //if(addressOffset< addressOffset + memoryReadSize){
                //printf("Level bu %d, bucketsFromStart %d, read from begining %d to %d",i+1,bucketsFromStart[i],addressOffset,addressOffset + memoryReadSize);

                //print current storage at this level
                //dumpStorageLevel(i);
                //end for debug

               //read memory
                for (int j=addressOffset ; j < addressOffset + memoryReadSize ; j++){
                        metaBlock visited_block;
                        
                        //increase temp_path if needed based on lexical path order
                        if(j > addressOffset && (j % Z) == 0)
                            temp_path++;

                        visited_block.hash_bid = store[j].id;
                        visited_block.offset = j % Z;
                        visited_block.path = temp_path % (int) pow(2,i);
                        visited_block.index = (Z * i) + (j % Z);
                        visited_block.bu = i+1 ; //bu level

                        //add to the set v
                        v.push_back(visited_block);

                        //reset store[j]
                        store[j].id =  0xFFFFFFFF;
                }

                //print indices j all above for testing.
                //debug from eviction 0	
        }


        return v;
    }

    void dumpStorageLevel(int level){

        printf("Level bu %d",level+1);
        //dump all level to test
        int startingOffsetAtLevel = (int) (pow(2, level)-1); 
        if(level==0){
            startingOffsetAtLevel = 0;
        }

        int nextLevel =      (int) (pow(2, level+1)-1); 
        //for testing
        std::string str;
        for(int xx=startingOffsetAtLevel*Z; xx < nextLevel*Z;xx++){
            str.append(",");
            str.append(std::to_string((int)store[xx].id));
        }



        printf("Storage this level: %s", (char*)str.c_str());
    }

    void uploadChunk(int* startingBucket,int* numOfBuckets, const vector<metaBlock> &updated_blocks){
        
        int startingOffsetAtLevel;
		int nextBlock = 0;

        ///scanning each level (partition) to write
		for(int level = depth; level >= 0; level--) {

			/*  Identify wrap around for level based on numOfBuckets */
            //identify the beginning of that level in the memory disk

			if(level == 0) {
				startingOffsetAtLevel = 0;
			}
			else {
				startingOffsetAtLevel = (int) (pow(2, level)-1);
			}

			int bucketsUptoEnd = 0;
			int bucketsFromStart= 0; 
			
            //find where to write from beginning to the end and for wrapping at that starting offset 
			int t = 0;
			while(t < numOfBuckets[level]) {
					if((startingBucket[level]+t) < ((int) (pow(2, level))))
						bucketsUptoEnd += 1;
					else
						bucketsFromStart += 1;
					t++;
			}

			int temp = 0;
			int memoryOffset = (startingBucket[level]+startingOffsetAtLevel);
			int cntr = 0;            
			
			/* upload buckets till end of level from starting bucket */
			while(temp < bucketsUptoEnd) {
				temp++;
				cntr++;
            }

            uint32_t tmp[cntr*Z]; //tmp array to replace the current in the store memory
            for(int i=0; i < Z *cntr; i++){
                tmp[i] = updated_blocks[nextBlock].hash_bid;
                nextBlock++;
            }	

            //start writing to the memory array
            int f=0;
            while(f<cntr*Z){
                store[(memoryOffset*Z)+f].id= tmp[f];
                f++;
            }

			/* upload buckets after wrap around from start of level */
			if(bucketsFromStart > 0) {
                //reset the temp variables
				temp = 0;
				memoryOffset = startingOffsetAtLevel;
				cntr = 0;

				while(temp < bucketsFromStart) {
					cntr++;
					temp++;                    
                }

                uint32_t tmp1[cntr*Z]; //tmp array to replace the current in the store memory
                for(int i=0; i < Z *cntr; i++){
                    tmp1[i] = updated_blocks[nextBlock].hash_bid;
                    nextBlock++;
                }

                //start writing to the memory array
                f=0;
                while(f<cntr*Z){
                    store[(memoryOffset*Z)+f].id= tmp1[f];
                    f++;
                }
            }
        }
    }

public:
    rORAM(int depth, uint8_t bucket_size, int _oramID, int rangeSupport) {
       
        // assign basic parameters
        this->depth = depth;
        N = pow(2, depth + 1) - 1; //N is the total bucket~ tree size
        leafNum = pow(2,depth); //ranging from [0, 2^depth)
        Z = bucket_size;
    
        //printf("Tree size %d",N);

        // initialise the position map
        position = new uint32_t[get_block_count()];
   
        // initialise the data store
        store = new rBlock[get_block_count()];
        // fill the blocks with dummy data
        for(int i = 0; i < N; i++) {
            for(int z = 0; z < Z; z++) {
                store[i * Z + z].id = 0xFFFFFFFF; //set to dummy bid
            }
        }

        // randomise the path: note that, later we still get by range- thus some positions are redundant
        for(int i = 0; i < get_block_count(); i++) {
            position[i] = random_path();
        }

        // clear the stash
        stash_size = ORAM_STASH_SIZE * (rangeSupport+1);
        stash = new rStashB(oramID, stash_size); //since upload need to push to the stash 

        oramID     =   _oramID;      
        rangeSize = rangeSupport;
        evictCounter = 0 ;
    }

    ~rORAM() {
        // clear the position map and the stash
        clear();
        // remove data
        delete position;
        delete store;
    }

    int getCurrentEvictionPath(){
        return (int)evictCounter;
    }

    int getORAMDepth(){
        return depth;
    }

    void clear() {
        stash->clear();
        // refill positions
        for(int i = 0; i < get_block_count(); i++) {
            position[i] = random_path();
        }
        // reset the store
        for(int i = 0; i < N; i++) {
            for(int z = 0; z < Z; z++) {
                store[i * Z + z].id = 0xFFFFFFFF;
            }
        }
    }

//    void get_dist(uint32_t *dist) {
//        for(int i = 0; i < N; i++) {
//            for(int z = 0; z < Z; z++) {
//                dist[store[i *Z + z].block[0]] += selector(1, 0, (store[i * Z + z].id != 0xFFFFFFFF));
//            }
//        }
//    }

    uint32_t get_block_count() {
        return N * Z;
    }


    uint32_t getRangeSize(){
        return rangeSize;
    }

    uint32_t getStashSize(){
        return stash_size;
    }

    void stashUpload(metaBlock *mBlocks, int rangeSize){ //the function returns the index avalable in the stash

        int random_path = get_random_path();        //retrieve the first random path one from the tree T_r 

        for(int id_offset = 0; id_offset < rangeSize; id_offset++)
        {
            //set path
            if(id_offset==0){
                mBlocks[id_offset].path =  random_path;
            }else{
                mBlocks[id_offset].path = get_lexical_path_order(random_path);      
                random_path++;
            }

            //find an unoccupied or dummy location in the stash_r and update index (or read and update)
            mBlocks[id_offset].index =  write_stash(mBlocks[id_offset].hash_bid);

            uint32_t found = read_stash(mBlocks[id_offset].hash_bid);
            //printf("\n-insert for bid ofset %d, saved index %d, found index %d\n",id_offset, mBlocks[id_offset].index,found);

        }
    }


    //for testing purpose - check whether the block is in the stash
    //int found = rORAMTracker[r]->blockInStash_test( b.hash_bid);
    //printf("found in stash bid %d", (int) found);

    void blockInStash(metaBlock *aBlock){
        uint32_t found = read_stash(aBlock->hash_bid);
        //printf("Check found in rORAM %d",found);
        //if((int)found>=0){
        //    aBlock->bu = 0;
        //    aBlock->offset =  found;
        //}

       // printf("retest found %d", found);
       // int new_bu = selector(aBlock->bu, 0 , found == -1); //aBlock->bu
       // int new_offset =  selector(aBlock->offset, found , found == -1);  //aBlock->offset

        //start oblivious code
        uint8_t value_tmp[4];
        uint32_t dummy = 0 ;
        u32_to_u8(dummy,value_tmp);

        uint8_t value_dst[4];
        u32_to_u8(aBlock->bu,value_dst);


        o_memcpy_byte(ocmp_ge((int)found,0),value_dst,value_tmp,4);
        aBlock->bu = u8_to_u32(value_dst);

        u32_to_u8(found,value_tmp);
        u32_to_u8(aBlock->offset,value_dst);
        o_memcpy_byte(ocmp_ge((int)found,0),value_dst,value_tmp,4);
        aBlock->offset = u8_to_u32(value_dst);
        //end oblivious code


    }

    //int blockInStash_test(uint32_t bidtest){
    //    return read_stash(bidtest);
    //}

    vector<metaBlock> retrieveBlocksOnEvictedPaths(){

        //pull blocks in the eviction paths (2^r paths) from the tree to the stash_r using fetch_path PathORAM
        //reset those visited blocks in the paths in the memory to be dummy 0xFFFFFFFF
        vector<metaBlock> blocks_on_paths = batchReadPaths(evictCounter,rangeSize);
        return blocks_on_paths;
      
    }

    void oblivStashInsert(vector<metaBlock> &blocks_on_paths){
        
        //move to stash and updates the location s in the stash with the id
        for(metaBlock b: blocks_on_paths){
            //find an unoccupied or dummy location in the stash_r and update location s in the stash_r
            //report stash if overflow
            b.s =  write_stash(b.hash_bid);
            //and also update in blocks_on_paths
        }

    }

    vector<metaBlock>  logicalEvictionFromStash(PathORAM *block_state){
      
        vector<metaBlock> updated_blocks;

        int bucketLabel[depth+1];//tracking the first path in each level to be written in the rORAM
        int numberOfBuckets[depth+1]; //number of bucket in each level to be written in the rORAM

        int nextLeafLabel = (int)evictCounter;

        std::map<uint32_t, metaBlock> stash_meta_block;

        //stash->scan(m,m1,block_state) to find out the meta data of blocks in the current Stash
        stash->scan(stash_meta_block,block_state);

        //set dummy anchor run backward to extract the dummy
        int dummy_anchor_backward = getStashSize();

        //logical eviction is based on the rangeORAM, based on level
        for(int i = depth; i >=0; i--){

            int cur_buck_num = 0;

            //starting eviction in a batch of range in the current leaveLabel
            for(int l=0; l < (int)min((int)pow(2,i),rangeSize); l++){
                
                int leafLabel = (nextLeafLabel+l)%leafNum;
                
                //identify nodes that are in the same level of the current eviction path
                int k=0;
                rNode* iter = stash->get_start();

                //evict real bid to the bucket from the stash
                while(iter != nullptr && k < Z) {
                    if(iter->b.id != 0xFFFFFFFF && stash_meta_block.find(iter->b.id)!= stash_meta_block.end()) { //not a dummy bid
                        if(leafLabel % (int)pow(2,i) == (stash_meta_block.at(iter->b.id).path % (int)pow(2,i))) { //can reside in the same bucket
                        
                            //add the meta data of the current block to the list
                            metaBlock temp;
                            temp.hash_bid = iter->b.id;
                            temp.s = stash->search(iter->b.id); //from current location in the stash
                            temp.bu = i +1; // the bu level is the current depth+1 to destination
                            temp.path = stash_meta_block.at(iter->b.id).path;
                            temp.offset = k;
                            temp.index = getStashSize() + (temp.bu -1)*Z + temp.offset;
                            temp.counter = stash_meta_block.at(iter->b.id).counter;
                            temp.raw_bid = stash_meta_block.at(iter->b.id).raw_bid;

                            //printf("\nOramID %d, leafLabel %d, block path %d, level %d\n",oramID, leafLabel,stash_meta_block.at(iter->b.id).path,i);
                            //printf("Evict: OramID %d, hbid %d, block id %d, index %d, bu %d, offset %d\n",oramID, temp.hash_bid, temp.raw_bid, temp.index,temp.bu,temp.offset);

                            k++;

                            updated_blocks.push_back(temp);

                            //remove the value from the hashmap 
                            stash_meta_block.erase(iter->b.id);

                            //reset stash at those places while looping
                            stash->erase(iter);
                            iter = nullptr;
                        }
                    }

                    if(iter!=nullptr) { 
                        iter = iter->prev;
                    }
                    else {
                        iter = stash->get_start(); //rescanning the stash 
                    } 
                }

                //scan stash to find out bid ==-1 and to fulfill the bucket up to Z and also remove it from the stash( i.e., to 0)
                iter = stash->get_start();
                while(iter != nullptr && k < Z) {
                    if(iter->b.id == 0xFFFFFFFF) { //is a dummy bid
                        //add the meta data of the current dummy block to the list
                        metaBlock temp;
                        temp.hash_bid = iter->b.id;
                        temp.s = stash->search(iter->b.id); //from current location in the stash
                        temp.bu = i +1; // the bu level is the current depth+1 to destination
                        temp.path = leafLabel;
                        temp.offset = k;
                        temp.index = getStashSize() + (temp.bu -1)*Z + temp.offset;
                        sgx_read_rand((unsigned char *) &temp.counter, 4); 
                        sgx_read_rand((unsigned char *) &temp.raw_bid, 4); 

                        k++;

                        updated_blocks.push_back(temp);

                        //reset stash at those places while looping
                        stash->erase(iter);
                        iter = nullptr;
                    
                    }

                    if(iter!=nullptr) { 
                        iter = iter->prev;
                    }
                    else {
                        iter = stash->get_start(); //rescanning the stash 
                    } 
                }

                //if even not have -1 in the stash, just gen -1 from the last index of the stash
                while(k < Z){
                    //add the meta data of the current dummy block to the list
                    metaBlock temp;
                    temp.hash_bid = 0xFFFFFFFF;
                    temp.s = dummy_anchor_backward;  //from the last location in the stash
                    temp.bu = i +1; // the bu level is the current depth+1 to destination
                    temp.path = leafLabel;
                    temp.offset = k;
                    temp.index = getStashSize() + (temp.bu -1)*Z + temp.offset;
                    sgx_read_rand((unsigned char *) &temp.counter, 4); 
                    sgx_read_rand((unsigned char *) &temp.raw_bid, 4); 

                    k++;

                    updated_blocks.push_back(temp);

                    //reset the last location in the Stash
                    dummy_anchor_backward--;
                }

                //update the cur_buck_num to be written in this level
                cur_buck_num++;

            } 

            //for this tree level i, set bucketLabel[i] is the starting location to modify in the tree's memory
			if(i > 0) //get the current path of this bucket
				bucketLabel[i] = (int) (nextLeafLabel% (int)pow(2,i));
			else
				bucketLabel[i] = 0; //set the path for the root is 0

            //update the number of bucket to be written into the tree's memory at this level
            numberOfBuckets[i] = cur_buck_num;
        }

        //update the memory of this rangeORAM
        uploadChunk(bucketLabel,numberOfBuckets,updated_blocks);

        //update evictCounter
        evictCounter = (evictCounter + rangeSize) % (N/2);

        return updated_blocks;
    }

    vector<metaBlock> readRange(metaBlock *mBlocks, int rangeQuery){

        vector<metaBlock> result, tmp;
        int id_offset, id_offset1;

        //test print stash
        //stash->printStash();

        tmp = batchReadPaths(mBlocks[0].path,rangeQuery);
        
        //for testing
        //std::string str;
        //for(int z = 0; z < tmp.size(); ++z) { 
        //    str.append(",");
        //    str.append(std::to_string((int)tmp[z].hash_bid) );
        //}    
        //printf("sample set %s", (char*)str.c_str());
        //end test


        //filter based on deterministic (bu,o) and path % at the same level, push to result and return.
        for(id_offset = 0; id_offset < rangeQuery; ++id_offset)
        {   
            bool test= false;
            for(int i = 0; i < tmp.size(); ++i) {//for(metaBlock b: tmp){  
                metaBlock b = tmp[i];
                
                int retrievedPath = b.path % (int) pow(2, b.bu-1);
                int checkedPath = mBlocks[id_offset].path % (int)pow(2, mBlocks[id_offset].bu-1);
 
                if(b.bu == mBlocks[id_offset].bu && b.offset == mBlocks[id_offset].offset && retrievedPath==checkedPath && test==false)  {
                    result.push_back(b);
                    //printf("block bid original found %d", mBlocks[id_offset].hash_bid);
                    //printf("block bid search found %d",b.hash_bid);
                    test = true;
                    tmp.erase(tmp.begin()+i);
                    i--;
                }  
        
            }

            //printf("retest id_offset %d",id_offset);
            if(mBlocks[id_offset].hash_bid != result[result.size()-1].hash_bid){
                printf("block bid %d not found", mBlocks[id_offset].hash_bid);
                //dumpStorageLevel(mBlocks[id_offset].bu-1);
            }
        }

        return result;
    }
       
        //check

    /***
        //retrieve the first random path one from the tree T_r
        int random_path = get_random_path();        

        for(id_offset1 = 0; id_offset1 < rangeQuery; ++id_offset1)
        {
            //set lexical path to consecutive blocks
            if(id_offset1==0){
                mBlocks[id_offset1].path =  random_path;
            }else{
                mBlocks[id_offset1].path = get_lexical_path_order(random_path);      
                random_path++;
            }
        }
    ***/

    uint32_t getCurrent_Stash_Size(){
        return stash->getCurrentSize();
    }

    void insertStash_DummyBlocks(int filledUpStash){
        uint32_t bid = 0xFFFFFFFF;
        for (int i=0; i < filledUpStash; i++) {
            rBlock new_block;
            new_block.id = bid;
            stash->forceInsertDummy(new_block);

            //printf("\nCurrent stash size %d \n",  getCurrent_Stash_Size());
        }

    }

    rNode* get_Stash_start() {
        return stash->get_start();
    }

    void reset_stash_newIds(uint32_t *arr, int size){

        stash->clear(); //important to reset all the stash
        //printf("\nSize to write %d, stash current size %d\n", size , stash->getCurrentSize());

        for(int index=0; index < size; index++){
            rBlock new_block;
            new_block.id = arr[index];
            stash->forceResetStash(new_block,index);
        }

        //printf("\nAfter writing, stash current size %d\n", stash->getCurrentSize());
    }


    int insertStash_OneBlock(int bid){
        rBlock new_block;
        new_block.id = bid;
        return stash->insert(new_block);
    }

    uint32_t retrieve_lexical_path_order(uint32_t cur_path ){
        return get_lexical_path_order(cur_path);
    }

    uint32_t retrieve_random_path(){
        return random_path();
    }


    uint32_t retrieve_getDepth(){
        return depth;         // the depth of the tree
    }

};


#endif //rORAM_H