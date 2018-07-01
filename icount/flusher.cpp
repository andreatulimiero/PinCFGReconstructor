#include <stdio.h>
#include <time.h>
#include "pin.H"
#include "loggers.h"
#include "constants.h"
#include "utils.h"
#include "flusher.h"
#include "analyzer.h"

namespace flusher {
PIN_SEMAPHORE flusher_ready_sem;
PIN_SEMAPHORE flusher_sem;
THREADID requesting_thread_idx = -1;
doub_buf_trace_t* dbt;
FILE* f;
bool isPoisoned;

void flusherThread(void* arg) {
	INFO("[*]{Flusher} Started with OS_THREADID %d\n", PIN_GetTid());
	time_t tv, tx;
	while (1) {
		PIN_SemaphoreWait(&flusher_sem);
		START_STOPWATCH(tx);
		if (isPoisoned) return;
		INFO("[*]{Flusher} Received request from thread %d, flushing ...\n", requesting_thread_idx);
		dbt->isFlushing = true;
		if (!isOnline) {
			START_STOPWATCH(tv);
			flushTraceToFile(f, dbt->flush_buf, dbt->flush_buf_len);
			total_flusher_flushing_time += GET_STOPWATCH_LAP(tv);
			free(dbt->flush_buf);
		} else { /* TODO: Add analysis code for online version */ }
		dbt->isFlushing = false;
		dbt->isFlushBufEmpty = true;
		PIN_SemaphoreSet(&dbt->end_flush_sem);
		if (isPoisoned) return;
		PIN_SemaphoreClear(&flusher_sem);
		PIN_MutexUnlock(&flusher_req_mutex);
		total_flusher_time += GET_STOPWATCH_LAP(tx);
		INFO("[*]{Flusher} Completed request from thread %d, waiting for incoming requests ...\n", requesting_thread_idx);
	}
}
}