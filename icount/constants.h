#pragma once

#define Kb 1024
#define Mb (1024*Kb)
#define Gb (1024*Mb)

#define CACHE_LINE_SIZE 64
#define MAIN_THREAD_FAVOR_FACTOR 4

#define INS_DELIMITER '\n'
#define ADDR_CHARS sizeof(ADDRINT)

#define THREAD_BUFFER_SIZE 30*Mb
#define TRACE_LIMIT 2047*Mb
#define TRACE_NAME_LENGTH_LIMIT 128
#define THREADS_MAX_NO 256