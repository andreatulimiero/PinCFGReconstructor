#pragma once

typedef struct trace_s {
	char* buf;
	size_t cursor;
} trace_t;

#define Kb 1024
#define Mb 1024*Kb
#define Gb 1024*Mb

#define INS_DELIMITER '\n'
#define ADDR_CHARS sizeof(ADDRINT)

#define RAW_TRACE_BUF_SIZE 512*Kb
#define TRACE_LIMIT 256*Mb
#define TRACE_NAME_LENGTH_LIMIT 128
#define THREADS_MAX_NO 256