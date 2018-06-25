#include <stdio.h>
#include "pin.H"
#include "loggers.h"
#include "constants.h"
#include "flusher.h"
#include "analyzer.h"

namespace flusher {
PIN_SEMAPHORE flusher_sem;
THREADID requesting_thread_idx = -1;
doub_buf_trace_t* dbt;
FILE* f;

void flusherThread(void* arg) {
	PIN_SemaphoreInit(&flusher_sem);
	PIN_SemaphoreSet(&flusher_ready_sem);
	INFO("[*]{Flusher} Setup completed\n");
	while (1) {
		PIN_SemaphoreWait(&flusher_sem);
		INFO("[*]{Flusher} Received request from thread %d, flushing ...\n", requesting_thread_idx);
		dbt->isFlushing = true;
		printRawTrace(f, dbt->flush_buf, dbt->flush_buf_len);
		free(dbt->flush_buf);
		INFO("[*]{Flusher} Finished writing for thread %d\n", requesting_thread_idx);
		dbt->isFlushing = false;
		dbt->isFlushBufEmpty = true;
		PIN_SemaphoreSet(&dbt->end_flush_sem);
		PIN_SemaphoreClear(&flusher_sem);
		PIN_MutexUnlock(&flusher_req_mutex);
		INFO("[*]{Flusher} Completed request from thread %d, waiting for incoming requests ...\n", requesting_thread_idx);
	}
}
}