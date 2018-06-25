#include <stdio.h>
#include "pin.H"
#include "loggers.h"
#include "constants.h"
#include "flusher.h"
#include "analyzer.h"

namespace flusher {
PIN_SEMAPHORE flusher_sem;
PIN_SEMAPHORE end_flush_sem;
THREADID requesting_thread_idx = -1;
char* buf;
size_t buf_len;
FILE* f;

void flusherThread(void* arg) {
	PIN_SemaphoreInit(&flusher_sem);
	PIN_SemaphoreInit(&end_flush_sem);
	INFO("[*]{Flusher} Setup completed\n");
	while (1) {
		PIN_SemaphoreWait(&flusher_sem);
		INFO("[*]{Flusher} Received request from thread %d, flushing ...\n", requesting_thread_idx);
		printRawTrace(f, buf, buf_len);
		free(buf);
		INFO("[*]{Flusher} Finished writing for thread %d\n", requesting_thread_idx);
		PIN_SemaphoreSet(&end_flush_sem);
		PIN_SemaphoreClear(&flusher_sem);
		INFO("[*]{Flusher} Completed request from thread %d, waiting for incoming requests ...\n", requesting_thread_idx);
	}
}
}