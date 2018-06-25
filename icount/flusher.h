#pragma once

namespace flusher {
void flusherThread(void* arg);

extern THREADID requesting_thread_idx;
extern char* buf;
extern size_t buf_len;
extern FILE* f;

extern PIN_SEMAPHORE flusher_sem;
extern PIN_SEMAPHORE end_flush_sem;
}