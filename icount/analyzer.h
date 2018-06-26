#pragma once
#include "constants.h"

#define TRACE_PADDING CACHE_LINE_SIZE - 12

typedef struct trace_s {
	char* buf;
	size_t cursor;
	size_t size;
	uint8_t _pad[TRACE_PADDING];
} trace_t;

typedef struct doub_buf_trace_s {
	trace_t trace;
	bool isFlushBufEmpty;
	bool isFlushing;
	char* flush_buf;
	size_t flush_buf_len;
	PIN_SEMAPHORE end_flush_sem;
} doub_buf_trace_t;

#define flushTraceToFile(f, buf, buf_len) { fwrite(buf, sizeof(char), buf_len, f); }
#define recordTraceToFile(f, buf, buf_len, trace) { fwrite(buf, sizeof(char), buf_len, f); trace->size += buf_len; }

extern size_t spawned_threads_no;
extern PIN_MUTEX flusher_req_mutex;
extern PIN_SEMAPHORE flusher_ready_sem;