#pragma once

typedef struct trace_s {
	char* buf;
	size_t cursor;
} trace_t;

#define Kb 1024
#define Mb (1024*Kb)
#define Gb (1024*Mb)

#define INS_DELIMITER '\n'
#define ADDR_CHARS sizeof(ADDRINT)

#define TRACE_LIMIT 128*Mb
#define TRACE_NAME_LENGTH_LIMIT 128
#define THREADS_MAX_NO 256