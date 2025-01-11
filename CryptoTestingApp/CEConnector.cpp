//
// Created by shangqi on 11/4/22.
//

#include "CEConnector.h"

CEConnector::CEConnector(){

    // rORAMNetwork rORAM_0, rORAM_1, rORAM_2, rORAM_3, rORAM_4, rORAM_5; //every 6 range belonging to the same edge server

    //setup the Thrift client to the EdgeServer ORAM
    shared_ptr<TTransport> socket(new TSocket(ComputingEngine_ip, ComputingEngine_port));
    transport = shared_ptr<TTransport>(new TFramedTransport(socket));
    shared_ptr<TProtocol> protocol(new apache::thrift::protocol::TBinaryProtocol(transport));
    _connector = new services::ComputingEngineClient(protocol);
    transport->open();

}

CEConnector::~CEConnector(){
    //destroy Thrift client
    free(_connector);
    transport->close();

}

void CEConnector::obliv_range_ret(blockPos *block_list,
                                  metaRangeRet_p1 *token_list_1, metaRangeRet_p2 *token_list_2,
                                  int range_index, int batch_size) {
    // request lists
    std::vector<services::tBlock_pos> block_request_list(batch_size);
    std::vector<services::tMetaRangeRet_p1> token_request_list_1(batch_size);
    std::vector<services::tMetaRangeRet_p2> token_request_list_2(batch_size);
    // copy all request info into request list
    for (int i = 0; i < batch_size; i++) {
        block_request_list[i].path = block_list[i].path;
        block_request_list[i].bu = block_list[i].bu;
        block_request_list[i].offset = block_list[i].offset;

        token_request_list_1[i].tag1.assign(token_list_1[i].tag1, token_list_1[i].tag1 + ENTRY_HASH_KEY_LEN_128);
        token_request_list_1[i].tag2.assign(token_list_1[i].tag2, token_list_1[i].tag2 + ENTRY_HASH_KEY_LEN_128);
        token_request_list_1[i].k_part1.assign(token_list_1[i].k_part1, token_list_1[i].k_part1 + VIDEO_BLOCK_SIZE);

        token_request_list_2[i].tag2.assign(token_list_2[i].tag2, token_list_2[i].tag2 + ENTRY_HASH_KEY_LEN_128);
        token_request_list_2[i].k_part2.assign(token_list_2[i].k_part2, token_list_2[i].k_part2 + VIDEO_BLOCK_SIZE);
        token_request_list_2[i].s = token_list_2[i].s;
        token_request_list_2[i].oramIndex = token_list_2[i].oramIndex;
    }
    // send the request to remote
    _connector->obliv_range_ret(block_request_list,
                                token_request_list_1, token_request_list_2,
                                range_index, batch_size);
}

void CEConnector::obliv_range_evict(metaOblivEvict *evict_list_1, metaOblivEvict *evict_list_2,
                       int range_index, int batch_size) {
    // request lists
    std::vector<services::tMetaOblivEvict> evict_request_list_1(batch_size);
    std::vector<services::tMetaOblivEvict> evict_request_list_2(batch_size);
    // copy all request info into request list
    for (int i = 0; i < batch_size; i++) {
        evict_request_list_1[i].tag.assign(evict_list_1[i].tag, evict_list_1[i].tag + ENTRY_HASH_KEY_LEN_128);
        evict_request_list_1[i].key_arr.assign(evict_list_1[i].key_arr, evict_list_1[i].key_arr + DPF_USER_KEY_PRG);
        evict_request_list_1[i].round = evict_list_1[i].round;
        evict_request_list_1[i].ks.assign(evict_list_1[i].ks, evict_list_1[i].ks + DPF_PARTY_KEY);
        evict_request_list_1[i].k_part.assign(evict_list_1[i].k_part, evict_list_1[i].k_part + VIDEO_BLOCK_SIZE);
        evict_request_list_1[i].oramIndex = evict_list_1[i].oramIndex;
        evict_request_list_1[i].path = evict_list_1[i].path;
        evict_request_list_1[i].bu = evict_list_1[i].bu;
        evict_request_list_1[i].offset = evict_list_1[i].offset;

        evict_request_list_2[i].tag.assign(evict_list_2[i].tag, evict_list_2[i].tag + ENTRY_HASH_KEY_LEN_128);
        evict_request_list_2[i].key_arr.assign(evict_list_2[i].key_arr, evict_list_2[i].key_arr + DPF_USER_KEY_PRG);
        evict_request_list_2[i].round = evict_list_2[i].round;
        evict_request_list_2[i].ks.assign(evict_list_2[i].ks, evict_list_2[i].ks + DPF_PARTY_KEY);
        evict_request_list_2[i].k_part.assign(evict_list_2[i].k_part, evict_list_2[i].k_part + VIDEO_BLOCK_SIZE);
        evict_request_list_2[i].oramIndex = evict_list_2[i].oramIndex;
        evict_request_list_2[i].path = evict_list_2[i].path;
        evict_request_list_2[i].bu = evict_list_2[i].bu;
        evict_request_list_2[i].offset = evict_list_2[i].offset;
    }

    _connector->obliv_range_evict(evict_request_list_1, evict_request_list_2,
                                  range_index, batch_size);
}

void CEConnector::obliv_permute_re(metaPerRe *per_re_list_1, metaPerRe *per_re_list_2,
                      int range_index, int stash_size) {
    // request lists
    std::vector<services::tMetaPerRe> permute_re_request_list_1(stash_size);
    std::vector<services::tMetaPerRe> permute_re_request_list_2(stash_size);

    // copy all request info into request list
    for (int i = 0; i < stash_size; i++) {
        permute_re_request_list_1[i].originIndex = per_re_list_1[i].originIndex;
        permute_re_request_list_1[i].newIndex = per_re_list_1[i].newIndex;
        permute_re_request_list_1[i].k_part.assign(per_re_list_1[i].k_part, per_re_list_1[i].k_part + VIDEO_BLOCK_SIZE);

        permute_re_request_list_2[i].originIndex = per_re_list_2[i].originIndex;
        permute_re_request_list_2[i].newIndex = per_re_list_2[i].newIndex;
        permute_re_request_list_2[i].k_part.assign(per_re_list_2[i].k_part, per_re_list_2[i].k_part + VIDEO_BLOCK_SIZE);
    }

    _connector->obliv_permute_re(permute_re_request_list_1, permute_re_request_list_2,
                                 range_index, stash_size);
}

void CEConnector::pri_range_retrieve(metaPriRangeRet *range_retrieve_list_1, metaPriRangeRet *range_retrieve_list_2,
                        int range_index, int starting_index, int range_size) {
    // request lists
    std::vector<services::tMetaPriRangeRet> range_retrieve_request_list_1(range_size);
    std::vector<services::tMetaPriRangeRet> range_retrieve_request_list_2(range_size);

    // copy all request info into request list
    for (int i = 0; i < range_size; i++) {
        range_retrieve_request_list_1[i].tag.assign(range_retrieve_list_1[i].tag, range_retrieve_list_1[i].tag + ENTRY_HASH_KEY_LEN_128);
        range_retrieve_request_list_1[i].key_arr.assign(range_retrieve_list_1[i].key_arr, range_retrieve_list_1[i].key_arr + DPF_USER_KEY_PRG);
        range_retrieve_request_list_1[i].round = range_retrieve_list_1[i].round;
        range_retrieve_request_list_1[i].ks.assign(range_retrieve_list_1[i].ks, range_retrieve_list_1[i].ks + DPF_PARTY_KEY);
        range_retrieve_request_list_1[i].k_part.assign(range_retrieve_list_1[i].k_part, range_retrieve_list_1[i].k_part + VIDEO_BLOCK_SIZE);
        range_retrieve_request_list_1[i].oramIndex = range_retrieve_list_1[i].oramIndex;
        range_retrieve_request_list_1[i].path = range_retrieve_list_1[i].path;
        range_retrieve_request_list_1[i].bu_from = range_retrieve_list_1[i].bu_from;
        range_retrieve_request_list_1[i].bu_max_inclusive = range_retrieve_list_1[i].bu_max_inclusive;
        range_retrieve_request_list_1[i].offset = range_retrieve_list_1[i].offset;
        range_retrieve_request_list_1[i].stash_index = range_retrieve_list_1[i].stash_index;

        range_retrieve_request_list_2[i].tag.assign(range_retrieve_list_2[i].tag, range_retrieve_list_2[i].tag + ENTRY_HASH_KEY_LEN_128);
        range_retrieve_request_list_2[i].key_arr.assign(range_retrieve_list_2[i].key_arr, range_retrieve_list_2[i].key_arr + DPF_USER_KEY_PRG);
        range_retrieve_request_list_2[i].round = range_retrieve_list_2[i].round;
        range_retrieve_request_list_2[i].ks.assign(range_retrieve_list_2[i].ks, range_retrieve_list_2[i].ks + DPF_PARTY_KEY);
        range_retrieve_request_list_2[i].k_part.assign(range_retrieve_list_2[i].k_part, range_retrieve_list_2[i].k_part + VIDEO_BLOCK_SIZE);
        range_retrieve_request_list_2[i].oramIndex = range_retrieve_list_2[i].oramIndex;
        range_retrieve_request_list_2[i].path = range_retrieve_list_2[i].path;
        range_retrieve_request_list_2[i].bu_from = range_retrieve_list_2[i].bu_from;
        range_retrieve_request_list_2[i].bu_max_inclusive = range_retrieve_list_2[i].bu_max_inclusive;
        range_retrieve_request_list_2[i].offset = range_retrieve_list_2[i].offset;
        range_retrieve_request_list_2[i].stash_index = range_retrieve_list_2[i].stash_index;
    }

    _connector->pri_range_retrieve(range_retrieve_request_list_1, range_retrieve_request_list_1,
                                 range_index, starting_index, range_size);
}