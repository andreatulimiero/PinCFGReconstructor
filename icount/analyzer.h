#pragma once

typedef struct trace_s {
	size_t cursor;
	char* buf;
} trace_t;

typedef struct doub_buf_trace_s {
	trace_t trace;
	bool isFlushBufEmpty;
	char* flush_buf;
	size_t flush_buf_len;
	bool isFlushing;
} doub_buf_trace_t;

#define printRawTrace(f, buf, buf_len) { fwrite(buf, sizeof(char), buf_len, f); }

extern size_t spawned_threads_no;