#include "analyzer.h"
#include "loggers.h"

void writeReport() {
	if (isThreadFlushed) {
		REPORT("[i] Time spent to sync with flusher: %d ms\n", total_sync_time);
		REPORT("[i] Time spent waiting for flusher: %d ms\n", total_wait_time);
		REPORT("[i] Time the flusher was flushing: %d ms\n", total_flusher_flushing_time);
		REPORT("[i] Average time per flush: %d ms\n", total_flusher_flushing_time / total_flushes);
		REPORT("[i] Time the flusher was running: %d ms\n", total_flusher_time);
	} else if (isBuffered) {
		REPORT("[i] Time spent for flushing: %d ms\n", total_flushing_time);
		REPORT("[i] Average time per flush: %d ms\n", total_flushing_time / total_flushes);
	}
	if (isOnline && isBinaryPacked) {
		REPORT("[i] OEP found at 0x%x\n", upx_info->OEP);
		REPORT("[i] Time spent to create intervals %d ms\n", total_writed_intervals_creation_time);
		REPORT("[i] Time spent to check WXorX rule %d ms\n", total_wxorx_check_time);
	}
	REPORT("[i] Main thread time: %d ms\n", total_time);
	REPORT("Size: %d Mb\n", trace_size / Mb);
	REPORT("Threads spawned: %d\n", spawned_threads_no);
}