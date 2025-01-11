#ifndef CRYPTOENCLAVE_U_H__
#define CRYPTOENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_INIT_RORAM_STASH_DEFINED__
#define OCALL_INIT_RORAM_STASH_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_init_rORAM_Stash, (int rIndex, uint32_t stashSize, uint32_t range_Support));
#endif
#ifndef OCALL_STASH_UPLOAD_DEFINED__
#define OCALL_STASH_UPLOAD_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_Stash_upload, (const void* data_arr, int data_size, int meta_enc_block_size, int oramIndex));
#endif
#ifndef OCALL_OBLIVRET_DEFINED__
#define OCALL_OBLIVRET_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_oblivRet, (int oramIndex, int batch_size));
#endif
#ifndef OCALL_OBLIVEVICT_PUSHCE_DEFINED__
#define OCALL_OBLIVEVICT_PUSHCE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_oblivEvict_pushCE, (int treeIndex, int batch_size));
#endif
#ifndef OCALL_OBLIVEVICT_PUSHSTASH_DEFINED__
#define OCALL_OBLIVEVICT_PUSHSTASH_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_oblivEvict_pushStash, (int treeIndex));
#endif
#ifndef OCALL_OBLIVPERRE_DEFINED__
#define OCALL_OBLIVPERRE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_oblivPerRe, (int treeIndex, int stash_size));
#endif
#ifndef OCALL_OBLIVPRIRANGERETRIEVE_DEFINED__
#define OCALL_OBLIVPRIRANGERETRIEVE_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_oblivPriRangeRetrieve, (int treeIndex, int startingIndex, int rangeSize));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_uploadVideoLength(sgx_enclave_id_t eid, int vId, int videoRangeLength);
sgx_status_t ecall_uploadVideoInRange(sgx_enclave_id_t eid, int videoId, int rangeIndex, char* content, int content_length, void* obliv_ret_metaReturn_p1, void* obliv_ret_metaReturn_p2, void* obliv_ret_edge_request, void* obliv_batch_evict_p1, void* obliv_batch_evict_p2);
sgx_status_t ecall_fetchVideo(sgx_enclave_id_t eid, int videoId, void* per_re_p1, void* per_re_p2, void* pri_range_ret_p1, void* pri_range_ret_p2);
sgx_status_t ecall_reset(sgx_enclave_id_t eid);
sgx_status_t ecall_initial(sgx_enclave_id_t eid, int oram_video_map_memory, int oram_block_state_bytes, int roram_tracker_bytes);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
