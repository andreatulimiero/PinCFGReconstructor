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
	INFO("[*]{Flusher} Started\n");
	time_t tv;
	while (1) {
		PIN_SemaphoreWait(&flusher_sem);
		START_STOPWATCH(tv);
		if (isPoisoned) return;
		INFO("[*]{Flusher} Received request from thread %d, flushing ...\n", requesting_thread_idx);
		dbt->isFlushing = true;
		flushTraceToFile(f, dbt->flush_buf, dbt->flush_buf_len);
		free(dbt->flush_buf);
		dbt->isFlushing = false;
		dbt->isFlushBufEmpty = true;
		PIN_SemaphoreSet(&dbt->end_flush_sem);
		if (isPoisoned) return;
		PIN_SemaphoreClear(&flusher_sem);
		PIN_MutexUnlock(&flusher_req_mutex);
		total_flusher_time += GET_STOPWATCH_LAP(tv);
		INFO("[*]{Flusher} Completed request from thread %d, waiting for incoming requests ...\n", requesting_thread_idx);
	}
}
}