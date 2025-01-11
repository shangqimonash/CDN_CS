#include "EdgeConnector.h"

#include <string>
//#include <string.h> // memset(KF, 0, sizeof(KF));
#include "stdio.h"
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <sstream> //std::stringstream
#include <vector>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <cstring> 
#include <openssl/rand.h>
#include <algorithm>
#include <cmath>

#include <fstream>
    using std::ofstream;
    using std::cout;
    using std::endl;


EdgeConnector::EdgeConnector(){
    
    // rORAMNetwork rORAM_0, rORAM_1, rORAM_2, rORAM_3, rORAM_4, rORAM_5; //every 6 range belonging to the same edge server
    
	//setup the Thrift client to the EdgeServer ORAM
	shared_ptr<TTransport> socket(new TSocket(EdgeServer_ip, EdgeServer_port));
	transport = shared_ptr<TTransport>(new TBufferedTransport(socket));
	shared_ptr<TProtocol> protocol(new apache::thrift::protocol::TBinaryProtocol(transport));
    _connector = new services::EdgeServerClient(protocol);
	transport->open();

}

EdgeConnector::~EdgeConnector(){
	//destroy Thrift client
	free(_connector);
  	transport->close();

}

void EdgeConnector::init_rORAM_Stash(int rIndex, uint32_t stashSize, uint32_t range_Support){
    if(_connector->setup_rORAM_Stash(rIndex,stashSize,range_Support)) {
        return;
    }
    else {
        exit(-1);
    }
}

void EdgeConnector::stashUpload(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size){

    std::vector<services::tFullBlockContent> dataUpload;

    for(int j = 0; j < cur_batch_size; j++){
        services::tFullBlockContent v;
        v.leafLabel = m_e_Blocks[j].path;
        v.bucketLevel = m_e_Blocks[j].bu;
        v.bucketOffset = m_e_Blocks[j].offset;

        for(int b_index = 0 ; b_index < VIDEO_BLOCK_SIZE; b_index++){
             v.encData.push_back((int8_t)m_e_Blocks[j].enc_content[b_index]);

            //if(rIndex==0){
                //printf("%d",(int8_t)m_e_Blocks[j].enc_content[b_index]);
            //}
        }

        dataUpload.push_back(v);
    }
    
    if(_connector->stash_upload_by_oram_index(rIndex,dataUpload,cur_batch_size)) {
        return;
    } else {
        exit(-1);
    }
    
    //for testing purpose to retrieve data from STASH the data retrieve is corrected from outside
    //stash_Test( rIndex, m_e_Blocks,  cur_batch_size);

}

void EdgeConnector::edgeUpload(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size) {
    std::vector<services::tFullBlockContent> dataUpload;
    for(int j = 0; j < cur_batch_size; j++){
        services::tFullBlockContent v;
        v.leafLabel = m_e_Blocks[j].path;
        v.bucketLevel = m_e_Blocks[j].bu;
        v.bucketOffset = m_e_Blocks[j].offset;

        for(int b_index = 0 ; b_index < VIDEO_BLOCK_SIZE; b_index++){
            v.encData.push_back((int8_t)m_e_Blocks[j].enc_content[b_index]);

            //if(rIndex==0){
            //printf("%d",(int8_t)m_e_Blocks[j].enc_content[b_index]);
            //}
        }

        dataUpload.push_back(v);
    }
    if(_connector->edge_upload_by_locations(rIndex, dataUpload, dataUpload[0].leafLabel, cur_batch_size)) {
        return;
    } else {
        exit(-1);
    }
}

void EdgeConnector::stashRetrieveByLocations(int rIndex, meta_enc_block *m_e_Blocks, int blocknum){

	std::vector<services::tPhysicalLocation> locationSets;
    for(int l=0; l < blocknum; l++){
        services::tPhysicalLocation pp;
		pp.leafLabel = m_e_Blocks[l].path;
		pp.bucketLevel =  m_e_Blocks[l].bu;
		pp.bucketOffset = m_e_Blocks[l].offset;
		locationSets.push_back(pp);
	}

    std::vector<services::tFullBlockContent> enc_block_res;

	_connector->stash_fetch_by_locations(enc_block_res,rIndex,locationSets,blocknum);

    for(int l=0; l < blocknum; l++){
        for(int v=0; v < VIDEO_BLOCK_SIZE; v++){
            m_e_Blocks[l].enc_content[v] = (char)enc_block_res.at(l).encData.at(v);
        }
	}
}

void EdgeConnector::edgeRetrieveByLocations(int rIndex, meta_enc_block *m_e_Blocks, int blocknum) {
    std::vector<services::tPhysicalLocation> locationSets;
    for(int l=0; l < blocknum; l++){
        services::tPhysicalLocation pp;
        pp.leafLabel = m_e_Blocks[l].path;
        pp.bucketLevel =  m_e_Blocks[l].bu;
        pp.bucketOffset = m_e_Blocks[l].offset;
        locationSets.push_back(pp);
    }
    std::vector<services::tFullBlockContent> retrieved_block_res;
    _connector->edge_fetch_by_locations(retrieved_block_res, rIndex, locationSets, m_e_Blocks[0].path, blocknum);

    for(int l=0; l < blocknum; l++){
        for(int v=0; v < VIDEO_BLOCK_SIZE; v++){
            m_e_Blocks[l].enc_content[v] = (char)retrieved_block_res.at(l).encData.at(v);
        }
    }
}

void EdgeConnector::stash_Test(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size){
    //testing purpose
    meta_enc_block *m_e_Blocks2 = (meta_enc_block*)malloc(cur_batch_size * sizeof(meta_enc_block));
    for(int k=0 ; k < cur_batch_size ; k++){
        m_e_Blocks2[k].path = m_e_Blocks[k].path;
        m_e_Blocks2[k].bu = m_e_Blocks[k].bu;
        m_e_Blocks2[k].offset  = m_e_Blocks[k].offset;
    }


    stashRetrieveByLocations(rIndex,m_e_Blocks2,cur_batch_size);

    printf("\nRetrieve then \n");
    for(int v=0 ; v <  cur_batch_size; v++){ 
        //for(int j = 0; j < VIDEO_BLOCK_SIZE; j++)
            //printf("%d",(int8_t)m_e_Blocks[v].enc_content[j]);

        if(memcmp(m_e_Blocks[v].enc_content,m_e_Blocks2[v].enc_content,VIDEO_BLOCK_SIZE)==0){
            printf("\nOUTISDE-r=%d, l=%d,bu=%d,o=%d matched\n",rIndex,m_e_Blocks[v].path, m_e_Blocks[v].bu,m_e_Blocks[v].offset);
        }else{
            printf("\nOUTSIDE-r=%d, l=%d,bu=%d,o=%d not matched\n",rIndex,m_e_Blocks[v].path, m_e_Blocks[v].bu,m_e_Blocks[v].offset);
        }
    
        printf("\n");
    }
}
