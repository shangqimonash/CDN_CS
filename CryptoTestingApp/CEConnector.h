//
// Created by shangqi on 11/4/22.
//

#ifndef CDN_CS_CECONNECTOR_H
#define CDN_CS_CECONNECTOR_H

#include "../common/data_type.h"
#include "../common/config.h"
#include "Utils.h"
#include <vector>

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/server/TThreadedServer.h>
#include <thrift/transport/TBufferTransports.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>

#include "../gen-cpp/ComputingEngine.h"
#include "../gen-cpp/server_types.h"

using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::concurrency;
using namespace apache::thrift::server;
using namespace apache::thrift::transport;

class CEConnector {
public:
    CEConnector();
    ~CEConnector();

    void obliv_range_ret(blockPos *block_list,
                         metaRangeRet_p1 *token_list_1, metaRangeRet_p2 *token_list_2,
                         int range_index, int batch_size);

    void obliv_range_evict(metaOblivEvict *evict_list_1, metaOblivEvict *evict_list_2,
                           int range_index, int batch_size);

    void obliv_permute_re(metaPerRe *per_re_list_1, metaPerRe *per_re_list_2,
                          int range_index, int stash_size);

    void pri_range_retrieve(metaPriRangeRet *range_retrieve_list_1, metaPriRangeRet *range_retrieve_list_2,
                            int range_index, int starting_index, int range_size);

private:
    //std::pair<int, edge_server::EdgeServerClient> network_info;
    shared_ptr<TTransport> transport;
    services::ComputingEngineClient *_connector;


};


#endif //CDN_CS_CECONNECTOR_H
