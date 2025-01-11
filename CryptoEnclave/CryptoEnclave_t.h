#ifndef CRYPTOENCLAVE_T_H__
#define CRYPTOENCLAVE_T_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include "sgx_edger8r.h" /* for sgx_ocall etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

void ecall_uploadVideoLength(int vId, int videoRangeLength);
void ecall_uploadVideoInRange(int videoId, int rangeIndex, char* content, int content_length, void* obliv_ret_metaReturn_p1, void* obliv_ret_metaReturn_p2, void* obliv_ret_edge_request, void* obliv_batch_evict_p1, void* obliv_batch_evict_p2);
void ecall_fetchVideo(int videoId, void* per_re_p1, void* per_re_p2, void* pri_range_ret_p1, void* pri_range_ret_p2);
void ecall_reset(void);
void ecall_initial(int oram_video_map_memory, int oram_block_state_bytes, int roram_tracker_bytes);

sgx_status_t SGX_CDECL ocall_print_string(const char* str);
sgx_status_t SGX_CDECL ocall_init_rORAM_Stash(int rIndex, uint32_t stashSize, uint32_t range_Support);
sgx_status_t SGX_CDECL ocall_Stash_upload(const void* data_arr, int data_size, int meta_enc_block_size, int oramIndex);
sgx_status_t SGX_CDECL ocall_oblivRet(int oramIndex, int batch_size);
sgx_status_t SGX_CDECL ocall_oblivEvict_pushCE(int treeIndex, int batch_size);
sgx_status_t SGX_CDECL ocall_oblivEvict_pushStash(int treeIndex);
sgx_status_t SGX_CDECL ocall_oblivPerRe(int treeIndex, int stash_size);
sgx_status_t SGX_CDECL ocall_oblivPriRangeRetrieve(int treeIndex, int startingIndex, int rangeSize);
sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf);
sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter);
sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self);
sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
