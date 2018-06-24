#include <stdio.h>
#include "pin.H"
#include "constants.h"
#include "flusher.h"
#include "analyzer.h"

namespace flusher {
PIN_SEMAPHORE flusher_sem;
PIN_SEMAPHORE end_flush_sem;
char* buf;
size_t buf_len;
FILE* f;

void flusherThread(void* arg) {
	PIN_SemaphoreInit(&flusher_sem);
	PIN_SemaphoreInit(&end_flush_sem);
	while (1) {
		PIN_SemaphoreWait(&flusher_sem);
		printRawTrace(f, buf, buf_len);
		free(buf);
		PIN_SemaphoreSet(&end_flush_sem);
		PIN_SemaphoreClear(&flusher_sem);
	}
}
}