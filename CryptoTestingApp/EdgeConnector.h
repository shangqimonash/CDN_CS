#ifndef EDGE_NETWORKCON_H
#define EDGE_NETWORKCON_H


#include "../common//data_type.h"
#include "../common/config.h"
#include "Utils.h"
#include <vector>

#include <../gen-cpp/EdgeServer.h>
#include <../gen-cpp/server_types.h>
#include <thrift/protocol/TBinaryProtocol.h>    
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>


using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::server;
using namespace apache::thrift::transport;

using namespace std;
//using std::shared_ptr;
//using std::make_shared;


class EdgeConnector{
    public:
        EdgeConnector();
        ~EdgeConnector();

        void init_rORAM_Stash(int rIndex, uint32_t stashSize, uint32_t range_Support);
        void stashUpload(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size);
        void edgeUpload(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size);
        void stashRetrieveByLocations(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size);
        void edgeRetrieveByLocations(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size);
        void stash_Test(int rIndex, meta_enc_block *m_e_Blocks, int cur_batch_size);
    private:
        //std::pair<int, edge_server::EdgeServerClient> network_info;
        shared_ptr<TTransport> transport;
        services::EdgeServerClient *_connector;
};
 
#endif