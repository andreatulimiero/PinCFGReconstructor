#pragma once
#include <list>
#include "constants.h"
#include "proc.h"

#define TRACE_PADDING CACHE_LINE_SIZE - 12

typedef struct trace_s {
	size_t cursor;
	char* buf;
	uint8_t _pad[TRACE_PADDING];
	size_t buf_size;
} trace_t;

typedef struct doub_buf_trace_s {
	trace_t trace;
	bool isFlushBufEmpty;
	bool isFlushing;
	char* flush_buf;
	size_t flush_buf_len;
	PIN_SEMAPHORE end_flush_sem;
} doub_buf_trace_t;

// Stats
extern size_t total_flushes;

#define flushTraceToFile(f, buf, buf_len) { fwrite(buf, sizeof(char), buf_len, f); fflush(f); total_flushes++; }
//#define flushTraceToFile(f, buf, buf_len) { PIN_Sleep(70); total_flushes++;}

#define recordTraceInMemory(buf, buf_len, trace) {\
		memcpy(trace->buf + trace->cursor, buf, buf_len);\
		trace->cursor += buf_len;\
		trace_size += buf_len;\
	}

#define recordTraceToFile(f, buf, buf_len, trace) { flushTraceToFile(f, buf, buf_len); trace_size += buf_len; }

bool traceLimitGuard(trace_t* trace, size_t buf_len, THREADID thread_idx);

extern TLS_KEY tls_key;

extern PIN_LOCK pin_lock;
extern PIN_MUTEX flusher_req_mutex;
extern PIN_SEMAPHORE flusher_ready_sem;
extern PIN_THREAD_UID flusher_uid;

// Stats
extern time_t total_time;
extern time_t total_sync_time;
extern time_t total_wait_time;
extern time_t total_flusher_time;
extern time_t total_flusher_flushing_time;
extern time_t total_flushing_time;
extern time_t total_writed_intervals_creation_time;
extern time_t total_wxorx_check_time;

extern size_t spawned_threads_no;
extern size_t trace_size;
extern size_t total_flushes;
extern proc_info_t* proc_info;

// Configs
extern bool isBuffered;
extern bool isThreadFlushed;
extern bool isMainThreadFavored;
extern bool isOnline;
extern size_t trace_limit;
extern size_t thread_buffer_size;

extern bool isFirstIns;
extern const char* prog_name;

extern trace_t* traces[THREADS_MAX_NO];
extern FILE* files[THREADS_MAX_NO];
extern bool hasReachedTraceLimit[THREADS_MAX_NO];

// Online
extern upx_info_t* upx_info;
extern ADDRINT img_address;
extern bool isBinaryPacked;
extern FILE* upx_dump_file;
extern list<pair<ADDRINT, ADDRINT>> written_mem_intervals;
extern pair<ADDRINT, ADDRINT> main_img_memory;
extern pair<ADDRINT, ADDRINT> text_sec_memory;