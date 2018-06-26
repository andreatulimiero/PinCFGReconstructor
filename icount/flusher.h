#pragma once
#include "analyzer.h"

namespace flusher {
void flusherThread(void* arg);

extern THREADID requesting_thread_idx;
extern doub_buf_trace_t* dbt;
extern FILE* f;
extern bool isPoisoned;

extern PIN_SEMAPHORE flusher_sem;
extern PIN_SEMAPHORE flusher_ready_sem;
}