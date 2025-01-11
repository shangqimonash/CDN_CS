#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "../common/config.h"
#include "../common/data_type.h"

#include <inttypes.h>
#include <cstdint>
#include <chrono>
#include <iostream>
#include "Client.h"
#include "Utils.h"
#include "CEConnector.h"
#include "EdgeConnector.h"
#include <bits/stdc++.h>

//#include <google/protobuf/io/coded_stream.h>
//#include <google/protobuf/io/zero_copy_stream_impl.h>
//#include <boost/asio.hpp>

//#include <boost/shared_ptr.hpp>
//#include <boost/make_shared.hpp>

#define ENCLAVE_FILE "CryptoEnclave.signed.so"

EdgeConnector *edge_con;
CEConnector *ce_con;

//initial buffer for batching processing in ObliviousReturn
metaRangeRet_p1 *obliv_ret_metaReturn_p1;
metaRangeRet_p2 *obliv_ret_metaReturn_p2;
blockPos *obliv_ret_edge_request;

//init the buffer for batch processing in ObliviousBatchEvict
metaOblivEvict *obliv_batch_evict_p1;
metaOblivEvict *obliv_batch_evict_p2;

//init the buffer for batch processing OblivPerRe
metaPerRe * per_re_p1;
metaPerRe * per_re_p2;

//init the buffer for batch processing in OblivPriRangeRet
metaPriRangeRet * pri_range_ret_p1;
metaPriRangeRet * pri_range_ret_p2;


uint64_t timeSinceEpochMillisec() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void ocall_print_string(const char *str) {
    printf("%s", str);
}

void ocall_init_rORAM_Stash(int rIndex, uint32_t stashSize, uint32_t range_Support){
	printf("\tInit the CDN_Edge ORAM %d, stash size %d, range support %d\n",rIndex,stashSize,range_Support);
	edge_con->init_rORAM_Stash(rIndex,stashSize,range_Support);

}

void ocall_Stash_upload(const void *v_m_e_Blocks, int cur_batch_size, int meta_enc_block_size, int oramIndex){
	meta_enc_block *m_e_Blocks= (meta_enc_block*) v_m_e_Blocks;
	edge_con->stashUpload(oramIndex,m_e_Blocks,cur_batch_size);
	
}

void ocall_oblivRet(int treeIndex, int batch_size){ // using metaRangeRet, and usercheck- for (r,l,bu,o) with the batch size

	//metaRangeRet_p1 * obj1 = &obliv_ret_metaReturn_p1[0];
	//metaRangeRet_p2 * obj2 = &obliv_ret_metaReturn_p2[0];
   
    //print_bytes((uint8_t *)obj1->tag1,ENTRY_HASH_KEY_LEN_128);
    //print_bytes((uint8_t *)obj1->tag2,ENTRY_HASH_KEY_LEN_128); 
    //print_bytes((uint8_t *)obj1->k_part1,VIDEO_BLOCK_SIZE);

    //print_bytes((uint8_t *)obj2->tag2,ENTRY_HASH_KEY_LEN_128);
    //printf("\nobj2: rIndex %d, stashPos %d\n", obj2->oramIndex, obj2->s);

	printf("In untrusted\n");
    for (int i = 0; i < batch_size; i++) {
        printf(" l: %d , bu: %d , o: %d\n", obliv_ret_edge_request[i].path,  obliv_ret_edge_request[i].bu, obliv_ret_edge_request[i].offset);
    }


    //call thrift rpc for Edge server with (r,l,bu,o) using the tag t1 in the obliv_ret_metaReturn_p1
    ce_con->obliv_range_ret(obliv_ret_edge_request,
                            obliv_ret_metaReturn_p1, obliv_ret_metaReturn_p2,
                            treeIndex, batch_size);
    //call thrift rpc for DPF server
}

void ocall_oblivEvict_pushCE(int treeIndex, int batch_size){

    printf("In untrusted\n");
    for (int i = 0; i < batch_size; i++) {
        printf(" l: %d , bu: %d , o: %d\n", obliv_batch_evict_p1[i].path,  obliv_batch_evict_p1[i].bu, obliv_batch_evict_p1[i].offset);
    }

    //call thrift rpc to route to Er
    ce_con->obliv_range_evict(obliv_batch_evict_p1, obliv_batch_evict_p2,
                            treeIndex, batch_size);
}

void ocall_oblivEvict_pushStash(int treeIndex){

}

void ocall_oblivPerRe(int treeIndex, int stash_size){

	//printf("\nOblivPeRe Tree r-> %d\n", treeIndex);

	//print random blocks
	//metaPerRe  * obj1 = &per_re_p1[0];

	//printf("\nobj1: originalIndex %d, newIndex %d\n", obj1->originIndex, obj1->newIndex);
	//print_bytes((uint8_t *)obj1->k_part,VIDEO_BLOCK_SIZE);

	//metaPerRe  * obj2 = &per_re_p2[stash_size-1];
	//printf("\nobj2: originalIndex %d, newIndex %d\n", obj2->originIndex, obj2->newIndex);
	//print_bytes((uint8_t *)obj2->k_part,VIDEO_BLOCK_SIZE);
    ce_con->obliv_permute_re(per_re_p1, per_re_p2,
                             treeIndex, stash_size);

}

void ocall_oblivPriRangeRetrieve(int treeIndex, int startingIndex, int rangeSize){
	printf("\noblivPriRangeReturn r-> %d\n", treeIndex);

	//print random blocks
    for (int i = 0; i < rangeSize; i++) {
        metaPriRangeRet * obj_i =  &pri_range_ret_p1[0];
        printf("\nobj%d: should query all blocks in the path %d, at offset %d, for all bu levels from %d to inclusived %d\n", i, obj_i->path, obj_i->offset, obj_i->bu_from, obj_i->bu_max_inclusive);
    }


	//key share
	//print_bytes((uint8_t *)obj1->k_part,VIDEO_BLOCK_SIZE);
	//key share
	//print_bytes((uint8_t *)obj2->k_part,VIDEO_BLOCK_SIZE);

    ce_con->pri_range_retrieve(pri_range_ret_p1, pri_range_ret_p2,
                               treeIndex, startingIndex, rangeSize);
}


//develop
int main()
{
	/* Setup enclave */
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;
	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}

	//--------------------------//
	printf("\n--Setup OCDN with Computing Engine/Edge Servers--\n");
	std::cout << timeSinceEpochMillisec() << std::endl;
	//open connection to Stash/Edge Servers and Computing Service servers
    ce_con = new CEConnector();
	edge_con = new EdgeConnector();


	//Enclave
	//about 2^8 leave movie nodes, each node in a 5-block node is 16 bytes	-> 1280 movies ids
	//about 2^16 movie block nodes, each node in a 5-block node is 16 bytes -> 327680 movie blocks
	ecall_initial(eid,TOTAL_MEM_VIDEO, TOTAL_MEM_BLOCK_STATE,TOTAL_MEM_RORAM_TRACKER);	
	
	std::cout << timeSinceEpochMillisec() << std::endl;


	//--------------------------//
	printf("\n-Upload video--\n");
	Client *myClient = new Client(); 
	int vId = 0;
	int videoRangeLength = 5; //up to ^5-1 blocks
	//myClient->CreateRawDoc(vId,videoRangeLength);
	
	//init the content buffer to read from the file
	Content *fetch_data;
	fetch_data = (Content*)malloc(sizeof(Content));

	//init the shared memory buffer between untrusted server and the Enclave to serve ObliviousRangeRet
	obliv_ret_metaReturn_p1 =  (metaRangeRet_p1 *) malloc(sizeof(metaRangeRet_p1)*OBLIV_RETURN_BATCH_SIZE);
	obliv_ret_metaReturn_p2 =  (metaRangeRet_p2 *) malloc(sizeof(metaRangeRet_p2)*OBLIV_RETURN_BATCH_SIZE);
	obliv_ret_edge_request  =  (blockPos*) malloc(sizeof(blockPos)*OBLIV_RETURN_BATCH_SIZE);

	//init the shared memory buffer between untrusted server and the Encave to serve ObliviousBatchEvict
	obliv_batch_evict_p1 = (metaOblivEvict *) malloc(sizeof(metaOblivEvict)*OBLIV_BATCH_EVICT_SIZE);
	obliv_batch_evict_p2 = (metaOblivEvict *) malloc(sizeof(metaOblivEvict)*OBLIV_BATCH_EVICT_SIZE);


	//init the shared memory buffer between untrustef server and the Enclave to serve OblivPerRer
	per_re_p1 = (metaPerRe *) malloc(sizeof(metaPerRe)*OBLIV_BATCH_PERE_SIZE);
	per_re_p2 = (metaPerRe *) malloc(sizeof(metaPerRe)*OBLIV_BATCH_PERE_SIZE);


	//init the shared memory buffer between untrusted server and the Enclave to serve OblivPriRangeRet
	pri_range_ret_p1 =  (metaPriRangeRet *) malloc(sizeof(metaPriRangeRet)*OBLIV_BATCH_RANGE_RETURN_SIZE);
	pri_range_ret_p2 =  (metaPriRangeRet *) malloc(sizeof(metaPriRangeRet)*OBLIV_BATCH_RANGE_RETURN_SIZE);


	std::cout << timeSinceEpochMillisec() << std::endl;

	//upload the videosize in videoMap
	ecall_uploadVideoLength(eid,vId,videoRangeLength);

	//upload the content in each range of the video
	for(int rangeIndex=0; rangeIndex < videoRangeLength;rangeIndex++){
		myClient->ReadRawDoc(vId,fetch_data,rangeIndex);
		ecall_uploadVideoInRange(eid,vId,rangeIndex,
								fetch_data->content,fetch_data->content_length,
								obliv_ret_metaReturn_p1,
								obliv_ret_metaReturn_p2,
								obliv_ret_edge_request,
								obliv_batch_evict_p1,
								obliv_batch_evict_p2);
	}

	std::cout << "\n"<< std::endl;
	std::cout << timeSinceEpochMillisec()  << std::endl;

	//clean up the share video
	free(fetch_data);

	//clean up shared memory used for Upload
    free(obliv_ret_metaReturn_p1);
	free(obliv_ret_metaReturn_p2);
	free(obliv_ret_edge_request);

	free(obliv_batch_evict_p1);
	free(obliv_batch_evict_p2);


	//--------------------------//
	printf("\n--Fetch video--\n");
	std::cout << timeSinceEpochMillisec() << std::endl;		

	ecall_fetchVideo(eid, vId,
					per_re_p1, per_re_p2,
					pri_range_ret_p1,pri_range_ret_p2);

	std::cout << timeSinceEpochMillisec() << std::endl;


	//clean up the shared memory used for Fetch
	free(per_re_p1);
	free(per_re_p2);

	free(pri_range_ret_p1);
	free(pri_range_ret_p2);

	//--------------------------//
	printf("\n--Reset OCDN--\n");

	//reset within the enclave
	ecall_reset(eid);

	//destroy enclave
	ret = SGX_SUCCESS;
	ret = sgx_destroy_enclave(eid);
	if (ret != SGX_SUCCESS)
	{
		printf("App: error %#x, failed to destroy enclave .\n", ret);
	}
	
	//clean up connection
	free(edge_con);
	free(myClient);



	printf("\n--Completing destroyed OCDN enclave and connections--\n");
	return 0;
}

