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

#define printRawTrace(f, buf, buf_len) {\
	for (size_t i = 0; i < buf_len; i++) { fputc(buf[i], f); }\
	}

extern size_t spawned_threads_no;