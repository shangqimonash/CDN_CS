#include "CryptoEnclave_t.h"

#include "sgx_trts.h" /* for sgx_ocalloc, sgx_is_outside_enclave */
#include "sgx_lfence.h" /* for sgx_lfence */

#include <errno.h>
#include <mbusafecrt.h> /* for memcpy_s etc */
#include <stdlib.h> /* for malloc/free etc */

#define CHECK_REF_POINTER(ptr, siz) do {	\
	if (!(ptr) || ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_UNIQUE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_outside_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define CHECK_ENCLAVE_POINTER(ptr, siz) do {	\
	if ((ptr) && ! sgx_is_within_enclave((ptr), (siz)))	\
		return SGX_ERROR_INVALID_PARAMETER;\
} while (0)

#define ADD_ASSIGN_OVERFLOW(a, b) (	\
	((a) += (b)) < (b)	\
)


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

static sgx_status_t SGX_CDECL sgx_ecall_uploadVideoLength(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_uploadVideoLength_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_uploadVideoLength_t* ms = SGX_CAST(ms_ecall_uploadVideoLength_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_uploadVideoLength(ms->ms_vId, ms->ms_videoRangeLength);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_uploadVideoInRange(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_uploadVideoInRange_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_uploadVideoInRange_t* ms = SGX_CAST(ms_ecall_uploadVideoInRange_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	char* _tmp_content = ms->ms_content;
	void* _tmp_obliv_ret_metaReturn_p1 = ms->ms_obliv_ret_metaReturn_p1;
	void* _tmp_obliv_ret_metaReturn_p2 = ms->ms_obliv_ret_metaReturn_p2;
	void* _tmp_obliv_ret_edge_request = ms->ms_obliv_ret_edge_request;
	void* _tmp_obliv_batch_evict_p1 = ms->ms_obliv_batch_evict_p1;
	void* _tmp_obliv_batch_evict_p2 = ms->ms_obliv_batch_evict_p2;



	ecall_uploadVideoInRange(ms->ms_videoId, ms->ms_rangeIndex, _tmp_content, ms->ms_content_length, _tmp_obliv_ret_metaReturn_p1, _tmp_obliv_ret_metaReturn_p2, _tmp_obliv_ret_edge_request, _tmp_obliv_batch_evict_p1, _tmp_obliv_batch_evict_p2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_fetchVideo(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_fetchVideo_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_fetchVideo_t* ms = SGX_CAST(ms_ecall_fetchVideo_t*, pms);
	sgx_status_t status = SGX_SUCCESS;
	void* _tmp_per_re_p1 = ms->ms_per_re_p1;
	void* _tmp_per_re_p2 = ms->ms_per_re_p2;
	void* _tmp_pri_range_ret_p1 = ms->ms_pri_range_ret_p1;
	void* _tmp_pri_range_ret_p2 = ms->ms_pri_range_ret_p2;



	ecall_fetchVideo(ms->ms_videoId, _tmp_per_re_p1, _tmp_per_re_p2, _tmp_pri_range_ret_p1, _tmp_pri_range_ret_p2);


	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_reset(void* pms)
{
	sgx_status_t status = SGX_SUCCESS;
	if (pms != NULL) return SGX_ERROR_INVALID_PARAMETER;
	ecall_reset();
	return status;
}

static sgx_status_t SGX_CDECL sgx_ecall_initial(void* pms)
{
	CHECK_REF_POINTER(pms, sizeof(ms_ecall_initial_t));
	//
	// fence after pointer checks
	//
	sgx_lfence();
	ms_ecall_initial_t* ms = SGX_CAST(ms_ecall_initial_t*, pms);
	sgx_status_t status = SGX_SUCCESS;



	ecall_initial(ms->ms_oram_video_map_memory, ms->ms_oram_block_state_bytes, ms->ms_roram_tracker_bytes);


	return status;
}

SGX_EXTERNC const struct {
	size_t nr_ecall;
	struct {void* ecall_addr; uint8_t is_priv; uint8_t is_switchless;} ecall_table[5];
} g_ecall_table = {
	5,
	{
		{(void*)(uintptr_t)sgx_ecall_uploadVideoLength, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_uploadVideoInRange, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_fetchVideo, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_reset, 0, 0},
		{(void*)(uintptr_t)sgx_ecall_initial, 0, 0},
	}
};

SGX_EXTERNC const struct {
	size_t nr_ocall;
	uint8_t entry_table[13][5];
} g_dyn_entry_table = {
	13,
	{
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
		{0, 0, 0, 0, 0, },
	}
};


sgx_status_t SGX_CDECL ocall_print_string(const char* str)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_str = str ? strlen(str) + 1 : 0;

	ms_ocall_print_string_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_print_string_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(str, _len_str);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (str != NULL) ? _len_str : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_print_string_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_print_string_t));
	ocalloc_size -= sizeof(ms_ocall_print_string_t);

	if (str != NULL) {
		ms->ms_str = (const char*)__tmp;
		if (_len_str % sizeof(*str) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, str, _len_str)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_str);
		ocalloc_size -= _len_str;
	} else {
		ms->ms_str = NULL;
	}
	
	status = sgx_ocall(0, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_init_rORAM_Stash(int rIndex, uint32_t stashSize, uint32_t range_Support)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_init_rORAM_Stash_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_init_rORAM_Stash_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_init_rORAM_Stash_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_init_rORAM_Stash_t));
	ocalloc_size -= sizeof(ms_ocall_init_rORAM_Stash_t);

	ms->ms_rIndex = rIndex;
	ms->ms_stashSize = stashSize;
	ms->ms_range_Support = range_Support;
	status = sgx_ocall(1, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_Stash_upload(const void* data_arr, int data_size, int meta_enc_block_size, int oramIndex)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_data_arr = data_size * meta_enc_block_size;

	ms_ocall_Stash_upload_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_Stash_upload_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(data_arr, _len_data_arr);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (data_arr != NULL) ? _len_data_arr : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_Stash_upload_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_Stash_upload_t));
	ocalloc_size -= sizeof(ms_ocall_Stash_upload_t);

	if (data_arr != NULL) {
		ms->ms_data_arr = (const void*)__tmp;
		if (memcpy_s(__tmp, ocalloc_size, data_arr, _len_data_arr)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_data_arr);
		ocalloc_size -= _len_data_arr;
	} else {
		ms->ms_data_arr = NULL;
	}
	
	ms->ms_data_size = data_size;
	ms->ms_meta_enc_block_size = meta_enc_block_size;
	ms->ms_oramIndex = oramIndex;
	status = sgx_ocall(2, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_oblivRet(int oramIndex, int batch_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_oblivRet_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_oblivRet_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_oblivRet_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_oblivRet_t));
	ocalloc_size -= sizeof(ms_ocall_oblivRet_t);

	ms->ms_oramIndex = oramIndex;
	ms->ms_batch_size = batch_size;
	status = sgx_ocall(3, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_oblivEvict_pushCE(int treeIndex, int batch_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_oblivEvict_pushCE_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_oblivEvict_pushCE_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_oblivEvict_pushCE_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_oblivEvict_pushCE_t));
	ocalloc_size -= sizeof(ms_ocall_oblivEvict_pushCE_t);

	ms->ms_treeIndex = treeIndex;
	ms->ms_batch_size = batch_size;
	status = sgx_ocall(4, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_oblivEvict_pushStash(int treeIndex)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_oblivEvict_pushStash_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_oblivEvict_pushStash_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_oblivEvict_pushStash_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_oblivEvict_pushStash_t));
	ocalloc_size -= sizeof(ms_ocall_oblivEvict_pushStash_t);

	ms->ms_treeIndex = treeIndex;
	status = sgx_ocall(5, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_oblivPerRe(int treeIndex, int stash_size)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_oblivPerRe_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_oblivPerRe_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_oblivPerRe_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_oblivPerRe_t));
	ocalloc_size -= sizeof(ms_ocall_oblivPerRe_t);

	ms->ms_treeIndex = treeIndex;
	ms->ms_stash_size = stash_size;
	status = sgx_ocall(6, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL ocall_oblivPriRangeRetrieve(int treeIndex, int startingIndex, int rangeSize)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_ocall_oblivPriRangeRetrieve_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_ocall_oblivPriRangeRetrieve_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_ocall_oblivPriRangeRetrieve_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_ocall_oblivPriRangeRetrieve_t));
	ocalloc_size -= sizeof(ms_ocall_oblivPriRangeRetrieve_t);

	ms->ms_treeIndex = treeIndex;
	ms->ms_startingIndex = startingIndex;
	ms->ms_rangeSize = rangeSize;
	status = sgx_ocall(7, ms);

	if (status == SGX_SUCCESS) {
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_oc_cpuidex(int cpuinfo[4], int leaf, int subleaf)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_cpuinfo = 4 * sizeof(int);

	ms_sgx_oc_cpuidex_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_oc_cpuidex_t);
	void *__tmp = NULL;

	void *__tmp_cpuinfo = NULL;

	CHECK_ENCLAVE_POINTER(cpuinfo, _len_cpuinfo);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (cpuinfo != NULL) ? _len_cpuinfo : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_oc_cpuidex_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_oc_cpuidex_t));
	ocalloc_size -= sizeof(ms_sgx_oc_cpuidex_t);

	if (cpuinfo != NULL) {
		ms->ms_cpuinfo = (int*)__tmp;
		__tmp_cpuinfo = __tmp;
		if (_len_cpuinfo % sizeof(*cpuinfo) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		memset(__tmp_cpuinfo, 0, _len_cpuinfo);
		__tmp = (void *)((size_t)__tmp + _len_cpuinfo);
		ocalloc_size -= _len_cpuinfo;
	} else {
		ms->ms_cpuinfo = NULL;
	}
	
	ms->ms_leaf = leaf;
	ms->ms_subleaf = subleaf;
	status = sgx_ocall(8, ms);

	if (status == SGX_SUCCESS) {
		if (cpuinfo) {
			if (memcpy_s((void*)cpuinfo, _len_cpuinfo, __tmp_cpuinfo, _len_cpuinfo)) {
				sgx_ocfree();
				return SGX_ERROR_UNEXPECTED;
			}
		}
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_wait_untrusted_event_ocall(int* retval, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_wait_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_wait_untrusted_event_ocall_t);

	ms->ms_self = self;
	status = sgx_ocall(9, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_untrusted_event_ocall(int* retval, const void* waiter)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_set_untrusted_event_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_untrusted_event_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_untrusted_event_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_untrusted_event_ocall_t);

	ms->ms_waiter = waiter;
	status = sgx_ocall(10, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_setwait_untrusted_events_ocall(int* retval, const void* waiter, const void* self)
{
	sgx_status_t status = SGX_SUCCESS;

	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);
	void *__tmp = NULL;


	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_setwait_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_setwait_untrusted_events_ocall_t);

	ms->ms_waiter = waiter;
	ms->ms_self = self;
	status = sgx_ocall(11, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

sgx_status_t SGX_CDECL sgx_thread_set_multiple_untrusted_events_ocall(int* retval, const void** waiters, size_t total)
{
	sgx_status_t status = SGX_SUCCESS;
	size_t _len_waiters = total * sizeof(void*);

	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = NULL;
	size_t ocalloc_size = sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);
	void *__tmp = NULL;


	CHECK_ENCLAVE_POINTER(waiters, _len_waiters);

	if (ADD_ASSIGN_OVERFLOW(ocalloc_size, (waiters != NULL) ? _len_waiters : 0))
		return SGX_ERROR_INVALID_PARAMETER;

	__tmp = sgx_ocalloc(ocalloc_size);
	if (__tmp == NULL) {
		sgx_ocfree();
		return SGX_ERROR_UNEXPECTED;
	}
	ms = (ms_sgx_thread_set_multiple_untrusted_events_ocall_t*)__tmp;
	__tmp = (void *)((size_t)__tmp + sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t));
	ocalloc_size -= sizeof(ms_sgx_thread_set_multiple_untrusted_events_ocall_t);

	if (waiters != NULL) {
		ms->ms_waiters = (const void**)__tmp;
		if (_len_waiters % sizeof(*waiters) != 0) {
			sgx_ocfree();
			return SGX_ERROR_INVALID_PARAMETER;
		}
		if (memcpy_s(__tmp, ocalloc_size, waiters, _len_waiters)) {
			sgx_ocfree();
			return SGX_ERROR_UNEXPECTED;
		}
		__tmp = (void *)((size_t)__tmp + _len_waiters);
		ocalloc_size -= _len_waiters;
	} else {
		ms->ms_waiters = NULL;
	}
	
	ms->ms_total = total;
	status = sgx_ocall(12, ms);

	if (status == SGX_SUCCESS) {
		if (retval) *retval = ms->ms_retval;
	}
	sgx_ocfree();
	return status;
}

