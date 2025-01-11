#include "CryptoEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_uploadVideoLength_t {
	int ms_vId;
	int ms_videoRangeLength;
} ms_ecall_uploadVideoLength_t;

typedef struct ms_ecall_uploadVideoInRange_t {
	int ms_videoId;
	int ms_rangeIndex;
	char* ms_content;
	int ms_content_length;
	void* ms_obliv_ret_metaReturn_p1;
	void* ms_obliv_ret_metaReturn_p2;
	void* ms_obliv_ret_edge_request;
	void* ms_obliv_batch_evict_p1;
	void* ms_obliv_batch_evict_p2;
} ms_ecall_uploadVideoInRange_t;

typedef struct ms_ecall_fetchVideo_t {
	int ms_videoId;
	void* ms_per_re_p1;
	void* ms_per_re_p2;
	void* ms_pri_range_ret_p1;
	void* ms_pri_range_ret_p2;
} ms_ecall_fetchVideo_t;

typedef struct ms_ecall_initial_t {
	int ms_oram_video_map_memory;
	int ms_oram_block_state_bytes;
	int ms_roram_tracker_bytes;
} ms_ecall_initial_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_init_rORAM_Stash_t {
	int ms_rIndex;
	uint32_t ms_stashSize;
	uint32_t ms_range_Support;
} ms_ocall_init_rORAM_Stash_t;

typedef struct ms_ocall_Stash_upload_t {
	const void* ms_data_arr;
	int ms_data_size;
	int ms_meta_enc_block_size;
	int ms_oramIndex;
} ms_ocall_Stash_upload_t;

typedef struct ms_ocall_oblivRet_t {
	int ms_oramIndex;
	int ms_batch_size;
} ms_ocall_oblivRet_t;

typedef struct ms_ocall_oblivEvict_pushCE_t {
	int ms_treeIndex;
	int ms_batch_size;
} ms_ocall_oblivEvict_pushCE_t;

typedef struct ms_ocall_oblivEvict_pushStash_t {
	int ms_treeIndex;
} ms_ocall_oblivEvict_pushStash_t;

typedef struct ms_ocall_oblivPerRe_t {
	int ms_treeIndex;
	int ms_stash_size;
} ms_ocall_oblivPerRe_t;

typedef struct ms_ocall_oblivPriRangeRetrieve_t {
	int ms_treeIndex;
	int ms_startingIndex;
	int ms_rangeSize;
} ms_ocall_oblivPriRangeRetrieve_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_init_rORAM_Stash(void* pms)
{
	ms_ocall_init_rORAM_Stash_t* ms = SGX_CAST(ms_ocall_init_rORAM_Stash_t*, pms);
	ocall_init_rORAM_Stash(ms->ms_rIndex, ms->ms_stashSize, ms->ms_range_Support);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_Stash_upload(void* pms)
{
	ms_ocall_Stash_upload_t* ms = SGX_CAST(ms_ocall_Stash_upload_t*, pms);
	ocall_Stash_upload(ms->ms_data_arr, ms->ms_data_size, ms->ms_meta_enc_block_size, ms->ms_oramIndex);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_oblivRet(void* pms)
{
	ms_ocall_oblivRet_t* ms = SGX_CAST(ms_ocall_oblivRet_t*, pms);
	ocall_oblivRet(ms->ms_oramIndex, ms->ms_batch_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_oblivEvict_pushCE(void* pms)
{
	ms_ocall_oblivEvict_pushCE_t* ms = SGX_CAST(ms_ocall_oblivEvict_pushCE_t*, pms);
	ocall_oblivEvict_pushCE(ms->ms_treeIndex, ms->ms_batch_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_oblivEvict_pushStash(void* pms)
{
	ms_ocall_oblivEvict_pushStash_t* ms = SGX_CAST(ms_ocall_oblivEvict_pushStash_t*, pms);
	ocall_oblivEvict_pushStash(ms->ms_treeIndex);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_oblivPerRe(void* pms)
{
	ms_ocall_oblivPerRe_t* ms = SGX_CAST(ms_ocall_oblivPerRe_t*, pms);
	ocall_oblivPerRe(ms->ms_treeIndex, ms->ms_stash_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_oblivPriRangeRetrieve(void* pms)
{
	ms_ocall_oblivPriRangeRetrieve_t* ms = SGX_CAST(ms_ocall_oblivPriRangeRetrieve_t*, pms);
	ocall_oblivPriRangeRetrieve(ms->ms_treeIndex, ms->ms_startingIndex, ms->ms_rangeSize);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[13];
} ocall_table_CryptoEnclave = {
	13,
	{
		(void*)CryptoEnclave_ocall_print_string,
		(void*)CryptoEnclave_ocall_init_rORAM_Stash,
		(void*)CryptoEnclave_ocall_Stash_upload,
		(void*)CryptoEnclave_ocall_oblivRet,
		(void*)CryptoEnclave_ocall_oblivEvict_pushCE,
		(void*)CryptoEnclave_ocall_oblivEvict_pushStash,
		(void*)CryptoEnclave_ocall_oblivPerRe,
		(void*)CryptoEnclave_ocall_oblivPriRangeRetrieve,
		(void*)CryptoEnclave_sgx_oc_cpuidex,
		(void*)CryptoEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_uploadVideoLength(sgx_enclave_id_t eid, int vId, int videoRangeLength)
{
	sgx_status_t status;
	ms_ecall_uploadVideoLength_t ms;
	ms.ms_vId = vId;
	ms.ms_videoRangeLength = videoRangeLength;
	status = sgx_ecall(eid, 0, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_uploadVideoInRange(sgx_enclave_id_t eid, int videoId, int rangeIndex, char* content, int content_length, void* obliv_ret_metaReturn_p1, void* obliv_ret_metaReturn_p2, void* obliv_ret_edge_request, void* obliv_batch_evict_p1, void* obliv_batch_evict_p2)
{
	sgx_status_t status;
	ms_ecall_uploadVideoInRange_t ms;
	ms.ms_videoId = videoId;
	ms.ms_rangeIndex = rangeIndex;
	ms.ms_content = content;
	ms.ms_content_length = content_length;
	ms.ms_obliv_ret_metaReturn_p1 = obliv_ret_metaReturn_p1;
	ms.ms_obliv_ret_metaReturn_p2 = obliv_ret_metaReturn_p2;
	ms.ms_obliv_ret_edge_request = obliv_ret_edge_request;
	ms.ms_obliv_batch_evict_p1 = obliv_batch_evict_p1;
	ms.ms_obliv_batch_evict_p2 = obliv_batch_evict_p2;
	status = sgx_ecall(eid, 1, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_fetchVideo(sgx_enclave_id_t eid, int videoId, void* per_re_p1, void* per_re_p2, void* pri_range_ret_p1, void* pri_range_ret_p2)
{
	sgx_status_t status;
	ms_ecall_fetchVideo_t ms;
	ms.ms_videoId = videoId;
	ms.ms_per_re_p1 = per_re_p1;
	ms.ms_per_re_p2 = per_re_p2;
	ms.ms_pri_range_ret_p1 = pri_range_ret_p1;
	ms.ms_pri_range_ret_p2 = pri_range_ret_p2;
	status = sgx_ecall(eid, 2, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_reset(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 3, &ocall_table_CryptoEnclave, NULL);
	return status;
}

sgx_status_t ecall_initial(sgx_enclave_id_t eid, int oram_video_map_memory, int oram_block_state_bytes, int roram_tracker_bytes)
{
	sgx_status_t status;
	ms_ecall_initial_t ms;
	ms.ms_oram_video_map_memory = oram_video_map_memory;
	ms.ms_oram_block_state_bytes = oram_block_state_bytes;
	ms.ms_roram_tracker_bytes = roram_tracker_bytes;
	status = sgx_ecall(eid, 4, &ocall_table_CryptoEnclave, &ms);
	return status;
}

