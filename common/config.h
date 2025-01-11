#ifndef CDN_CONFIG_H
#define CDN_CONFIG_H

#define GCM_KEY_SIZE	16
#define GCM_IV_SIZE     12
#define GCM_MAC_SIZE    16


#include <string>

#define bool_extend(val) (-(val) >> 32)
#define get_min(x, y) ((uint32_t) y & bool_extend(x > y)) | ((uint32_t) x & bool_extend(x <= y))
#define selector(x, y, bit) ((uint32_t) x & bool_extend(bit)) | ((uint32_t) y & bool_extend(!bit))
#define swap_threshold(negative_val, val) (negative_val > (val << 3))
#define get_flag(val) (((uint32_t)(val) & 0x80000000) == 0x80000000)
#define get_val(val) ((uint32_t)((val) & 0x7FFFFFFF))

// oram definitions for ORAM
#define TOTAL_MEM_VIDEO 1500 * 16 // 25 KB
#define TOTAL_MEM_BLOCK_STATE 600 * 1024 * 16   // 9600 KB
#define TOTAL_MEM_RORAM_TRACKER 600 * 1024 * 4 // 2400 KB

#define ORAM_DATA_SIZE 16// 16 bytes //used to store th block data in BLockState
#define ORAM_BLOCK_KEY_SIZE 4 // 4 bytes //used to store the id of the block in BLockState
#define ORAM_BUCKET_SIZE 5 //this Z is the same with Edge Server
#define ORAM_STASH_SIZE 105  // fp rate 2^(-128) accroding to the PathORAM paper, used for local ORAM in the controller


#define BUCKET_MEM (150 * 1024)
#define BUCKET_NUM (BUCKET_MEM / 64)

#define DPF_USER_KEY_PRG (11*4) //as of 11 blocks, each block contains (4 integers = 64 + 64 bytes) 
#define DPF_PARTY_KEY 52 //as of 52 uint8_t (see DPF.cpp) with the security param 128 bit

const std::string raw_video_dir=  "./videos/";
#define VIDEO_BLOCK_SIZE 2048 // block size for each edge server outside
#define VIDEO_UPLOAD_EDGE_BATCH_SIZE 100
#define OBLIV_RETURN_BATCH_SIZE 5000//100
#define OBLIV_BATCH_EVICT_SIZE 5000//100
#define OBLIV_BATCH_PERE_SIZE 5000//100
#define OBLIV_BATCH_RANGE_RETURN_SIZE 5000//100

const std::string EdgeServer_ip = "localhost";
const int EdgeServer_port = 9090;

const std::string ComputingEngine_ip = "localhost";
const int ComputingEngine_port = 9091;

#endif