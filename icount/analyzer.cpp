#include "pin.H"
#include <stdio.h>
#include <string.h>
#include "constants.h"
#include "loggers.h"
#include "analyzer.h"
#include "flusher.h"

static TLS_KEY tls_key = INVALID_TLS_KEY;
PIN_LOCK config_lock;
PIN_MUTEX flusher_req_mutex;
PIN_SEMAPHORE flusher_ready_sem;
PIN_THREAD_UID flusher_uid;

/** Custom options for our PIN tool **/
KNOB <BOOL> KnobIsBuffered(KNOB_MODE_WRITEONCE, "pintool",
	"buffered", "false", "whether or not the trace is buffered");
KNOB <BOOL> KnobIsThreadFlushed(KNOB_MODE_WRITEONCE, "pintool",
						   "thread_flushed", "false", "whether or not the trace has a thread for flushing");
KNOB <size_t> KnobTraceLimit(KNOB_MODE_WRITEONCE, "pintool",
	"trace_limit", "0", "size of the trace limit");
KNOB <size_t> KnobThreadBufferSize(KNOB_MODE_WRITEONCE, "pintool",
							 "thread_buffer_size", "0", "size of the per-thread buffer");

short unsigned int once;
bool isBuffered;
bool isThreadFlushed;
size_t trace_limit;
size_t thread_buffer_size;

size_t spawned_threads_no;
size_t trace_size;
bool isFirstIns = true;
const char* prog_name;

short unsigned int hasDone = 0;

trace_t* traces[THREADS_MAX_NO];
FILE* files[THREADS_MAX_NO];
bool hasReachedTraceLimit[THREADS_MAX_NO];

#define recordTraceInMemory(buf, buf_len, trace) {\
		memcpy(trace->buf + trace->cursor, buf, buf_len);\
		trace->cursor += buf_len;\
		trace_size += buf_len;\
	}

#define recordTraceToFile(f, buf, buf_len, trace) { fwrite(buf, sizeof(char), buf_len, f); trace_size += buf_len; }

void waitFlushEnd(doub_buf_trace_t* dbt, THREADID thread_idx) {
	INFO("[*]{Thread %d} Waiting for flush to be finished\n", thread_idx);
	PIN_SemaphoreWait(&dbt->end_flush_sem);
}

void requestFlush(doub_buf_trace_t* dbt, FILE* f, THREADID thread_idx) {
	INFO("[*]{Thread %d} Requested a flush\n", thread_idx);
	flusher::requesting_thread_idx = thread_idx;
	flusher::dbt = dbt;
	flusher::f = f;
	PIN_SemaphoreClear(&dbt->end_flush_sem);
	PIN_SemaphoreSet(&flusher::flusher_sem);
}

/* Here a request to the flusher might be carried out */
bool traceLimitGuard(trace_t* trace, size_t buf_len, THREADID thread_idx) {
	// If we reached the trace limit let's stop tracing
	if (trace_size + buf_len > trace_limit) {
		hasReachedTraceLimit[thread_idx] = true;
		return true;
	}
	// If we are in flushed mode no action is required
	if (!isBuffered) return false;

	// If we have not reached the main buffer maximum size no action is required
	if (trace->cursor + buf_len <= thread_buffer_size) return false;

	if (!isThreadFlushed) {
		INFO("[*] Thread buffer limit reached, flushing\n");
		flushTraceToFile(files[thread_idx], trace->buf, trace->cursor);
		trace->cursor = 0;
	} else {
		// Thread buffer limit has been reached, and flusher thread option is on
		doub_buf_trace_t* dbt = (doub_buf_trace_t*) trace;
		if (dbt->isFlushBufEmpty) {
			// Let's switch the buffers
			dbt->flush_buf = trace->buf;
			dbt->flush_buf_len = trace->cursor;
			trace->buf = (char*) malloc(sizeof(char) * trace_limit);
			trace->cursor = 0;
			dbt->isFlushBufEmpty = false;
			/* We try to gain the privilege to talk with the flusher
			On success => fire the flush
			On fail => move trace in a flush_buf pointer and try again later*/
			if (PIN_MutexTryLock(&flusher_req_mutex)) {
				requestFlush(dbt, files[thread_idx], thread_idx);
			} else {
				INFO("[*]{Thread %d} prepared for flush, trying next time\n", thread_idx);
			}
		} else {
			/* We need space to keep on writing
			Already asked a flush => wait for the flusher to end the flush
			Not asked a flush yet => wait to gain privilege to ask for it */
			if (dbt->isFlushing) {
				waitFlushEnd(dbt, thread_idx);
			} else {
				PIN_MutexLock(&flusher_req_mutex);
				requestFlush(dbt, files[thread_idx], thread_idx);
			}
		}
	}
	return false;
}

inline void INS_Analysis(char* buf, UINT32 buf_len, THREADID thread_idx) {
	trace_t* trace = (trace_t*)PIN_GetThreadData(tls_key, thread_idx);
	// Trace limit guard
	if (traceLimitGuard(trace, buf_len, thread_idx)) return;

	if (isBuffered)
		recordTraceInMemory(buf, buf_len, trace)
	else
		recordTraceToFile(files[thread_idx], buf, buf_len, trace);
}

inline void INS_JumpAnalysis(ADDRINT target_branch, INT32 taken, THREADID thread_idx) {
	if (!taken) return;
	trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	/* Allocate enough space in order to save:
	- @ char (1 byte)
	- address in hex format (sizeof(ADDRINT) * 2 bytes) + '0x' prefix (2 bytes)
	- \n delimiter (1 byte)
	- 0 terminator (1 byte)*/
	size_t buf_len = (sizeof(ADDRINT) * 2 + 5);
	// Trace limit guard
	if (traceLimitGuard(trace, buf_len, thread_idx)) return;

	char* buf = (char*)malloc(sizeof(char) * buf_len);
	buf[0] = '\n';
	buf[1] = '@';
	buf[buf_len - 1] = '\0';
	sprintf(buf + 2, "%x", target_branch);

	if (isBuffered)
		recordTraceInMemory(buf, buf_len, trace)
	else
		recordTraceToFile(files[thread_idx], buf, buf_len, trace);
}

void Ins(INS ins, void* v) {
	string disassembled_ins_s = INS_Disassemble(ins);
	/* Allocate enough space to save
	- Disassembled instruction (n bytes)
	- INS_DELIMITER (1 byte)
	- 0 terminator (1 byte)
	*/
	uint32_t disassembled_ins_len = strlen(disassembled_ins_s.c_str()) + 2;
	char* disassembled_ins = (char*)malloc(sizeof(char) * (disassembled_ins_len));
	disassembled_ins[0] = INS_DELIMITER;
	disassembled_ins[disassembled_ins_len - 1] = '\0';
	strcpy(disassembled_ins + 1, disassembled_ins_s.c_str());
	if (isFirstIns) {
		isFirstIns = false;
		strcpy(disassembled_ins, disassembled_ins + 1);
	}

	if (INS_IsBranchOrCall(ins)) {

		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR) INS_Analysis,
					   IARG_PTR,
					   disassembled_ins,
					   IARG_UINT32,
					   disassembled_ins_len,
					   IARG_THREAD_ID,
					   IARG_END);

		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR)INS_JumpAnalysis,
			IARG_BRANCH_TARGET_ADDR,
			IARG_BRANCH_TAKEN,
			IARG_THREAD_ID,
			IARG_END);
	}
}

void Img(IMG img, void* v) {
	if (strstr(IMG_Name(img).c_str(), prog_name))
		INFO("[+] Image %s loaded at %x\n", IMG_Name(img).c_str(), IMG_StartAddress(img));
}

void ThreadStart(THREADID thread_idx, CONTEXT* ctx, INT32 flags, VOID* v) {
	INFO("[*] Spawned thread %d\n", thread_idx);

	PIN_GetLock(&config_lock, thread_idx);
	/* Create output file */
	char filename[TRACE_NAME_LENGTH_LIMIT] = { 0 };
	sprintf(filename, "trace_%d.out", thread_idx);
	FILE* out = fopen(filename, "w+");
	INFO("[+] Created file %s\n", filename);

	/* Initialize a raw trace per thread */
	trace_t* trace;
	if (isThreadFlushed) {
		doub_buf_trace_t* dbt = (doub_buf_trace_t*) malloc(sizeof(doub_buf_trace_t));
		dbt->flush_buf = NULL; // We do not allocate space for this since this pointer will receive the trace's buf
		dbt->isFlushBufEmpty = true;
		dbt->isFlushing = false;
		PIN_SemaphoreInit(&dbt->end_flush_sem);
		trace = (trace_t*) dbt;
	} else
		trace = (trace_t*) malloc(sizeof(trace_t*));

	trace->buf = (char*) malloc(sizeof(char) * thread_buffer_size);
	if (trace->buf == NULL) {
		ERROR("[x] Not enough space to allocate the buffer\n");
		PIN_ExitApplication(1);
	}
	trace->cursor = 0;
	files[thread_idx] = out;

	traces[thread_idx] = trace;
	if (PIN_SetThreadData(tls_key, trace, thread_idx) == FALSE) {
		ERROR("[x] PIN_SetThreadData failed\n");
		PIN_ExitProcess(1);
	}
	spawned_threads_no++;
	PIN_ReleaseLock(&config_lock);
}

void ThreadFini(THREADID thread_idx, const CONTEXT* ctx, INT32 code, VOID* v) {
	trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	INFO("[*]{Thread %d} Ended, trace limit reached: %d\n", thread_idx, hasReachedTraceLimit[thread_idx]);
	if (isThreadFlushed) {
		doub_buf_trace_t* dbt = (doub_buf_trace_t*) trace;
		if (dbt->isFlushing) {
			INFO("[*]{Thread %d} Flusher still on duty, waiting for it to finish\n", thread_idx);
			waitFlushEnd(dbt, thread_idx);
		}
		// If there is something else left in the main buf we save it now
		if (trace->cursor > 0) {
			INFO("[*]{Thread %d} Flushing the remaining instructions\n", thread_idx);
			flushTraceToFile(files[thread_idx], trace->buf, trace->cursor)
		}
	} else if (isBuffered)
		flushTraceToFile(files[thread_idx], trace->buf, trace->cursor)
	INFO("[*]{Thread %d} Trace saved\n", thread_idx);
}

void Config() {
	isBuffered = KnobIsBuffered.Value();
	INFO("[*] Is Buffered? %d\n", isBuffered);

	isThreadFlushed = KnobIsThreadFlushed.Value();
	if (isThreadFlushed) isBuffered = true;
	INFO("[*] Is Thread flushed? %d\n", isThreadFlushed);

	trace_limit = KnobTraceLimit.Value() > 0 ? KnobTraceLimit.Value()*Mb : TRACE_LIMIT;
	INFO("[*] Trace limit: %dMb\n", trace_limit/Mb);

	thread_buffer_size = KnobThreadBufferSize.Value() > 0 ? KnobThreadBufferSize.Value()*Mb : THREAD_BUFFER_SIZE;
	INFO("[*] Thread buffer size: %dMb\n", thread_buffer_size/Mb);

}

void Usage() {
	ERROR("--- PinCFGReconstructor ---\n");
	ERROR((KNOB_BASE::StringKnobSummary() + "\n").c_str());
}

void PrepareForFini(void* v) {
	if (isThreadFlushed) {
		INFO("[*] Waiting for flusher to terminate\n");
		flusher::isPoisoned = true;
		PIN_SemaphoreSet(&flusher::flusher_sem);
		PIN_WaitForThreadTermination(flusher_uid, PIN_INFINITE_TIMEOUT, NULL);
	}
}

void Fini(INT32 code, VOID *v) {
	fprintf(stdout, "=======================\n");
	fprintf(stdout, "Trace finished\n");
	//fprintf(stdout, "Size: %d Kb\n", raw_trace->trace_size / (1024));
	fprintf(stdout, "Threads spawned: %d\n", spawned_threads_no);
	fprintf(stdout, "=======================\n");
}

int main(int argc, char *argv[]) {
	/* Init PIN */
	if (PIN_Init(argc, argv)) {
		Usage();
		return 0;
	}

	/* Prepare the Pintool */
	Config();

	/* Prepare TLS */
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY) {
		ERROR("[x] Number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit\n");
		PIN_ExitProcess(1);
	}

	/* Prepare Locks, Mutexes and Semaphores*/
	PIN_InitLock(&config_lock);
	PIN_MutexInit(&flusher_req_mutex);
	PIN_SemaphoreInit(&flusher_ready_sem);
	// Flusher
	PIN_SemaphoreInit(&flusher::flusher_sem);
	PIN_SemaphoreSet(&flusher::flusher_ready_sem);


	/* Spawn flusher thread if necessary */
	if (isThreadFlushed)
		PIN_SpawnInternalThread(flusher::flusherThread, 0, 0, &flusher_uid);

	prog_name = argv[argc - 1];
	INS_AddInstrumentFunction(Ins, 0);
	IMG_AddInstrumentFunction(Img, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddPrepareForFiniFunction(PrepareForFini, 0);
	PIN_AddFiniFunction(Fini, 0);

	PIN_StartProgram();
	return 0;
}
