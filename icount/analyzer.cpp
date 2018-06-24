#include "pin.H"
#include <stdio.h>
#include <string.h>
#include "constants.h"
#include "analyzer.h"
#include "flusher.h"

static TLS_KEY tls_key = INVALID_TLS_KEY;
PIN_LOCK config_lock;
PIN_MUTEX flusher_req_mutex;
PIN_THREAD_UID flusher_uid;

/** Custom options for our PIN tool **/
KNOB <BOOL> KnobIsBuffered(KNOB_MODE_WRITEONCE, "pintool",
	"buffered", "false", "whether or not the trace is buffered");
KNOB <BOOL> KnobIsThreadFlushed(KNOB_MODE_WRITEONCE, "pintool",
						   "thread_flushed", "false", "whether or not the trace has a thread for flushing");
KNOB <size_t> KnobTraceLimit(KNOB_MODE_WRITEONCE, "pintool",
	"trace_limit", "0", "size of the trace limit");

bool isBuffered;
bool isThreadFlushed;
size_t trace_limit;

size_t spawned_threads_no;
bool isFirstIns = true;
const char* prog_name;

short unsigned int hasDone = 0;

trace_t* traces[THREADS_MAX_NO];
FILE* files[THREADS_MAX_NO];
bool hasReachedTraceLimit[THREADS_MAX_NO];

#define recordInRawTrace(buf, buf_len, trace) {\
		memcpy(trace->buf + trace->cursor, buf, buf_len);\
		trace->cursor += buf_len;\
	}

void printAllRawTraces(FILE* f, trace_t* trace) {
	for (size_t i = 0; i < trace->cursor; i++) {
		fputc(trace->buf[i], f);
	}
}

void waitFlushEnd(doub_buf_trace_t* dbt) {
	PIN_SemaphoreWait(&flusher::end_flush_sem);
	dbt->isFlushing = false;
	dbt->isFlushBufEmpty = true;
	dbt->flush_buf = NULL;
	PIN_MutexUnlock(&flusher_req_mutex);
}

void requestFlush(doub_buf_trace_t* dbt, FILE* f) {
	flusher::buf = dbt->flush_buf;
	flusher::buf_len = dbt->flush_buf_len;
	flusher::f = f;
	dbt->isFlushing = true;
	PIN_SemaphoreClear(&flusher::end_flush_sem);
	PIN_SemaphoreSet(&flusher::flusher_sem);
}

/* Here a request to the flusher might be carried out */
bool traceLimitGuard(trace_t* trace, size_t buf_len, THREADID thread_idx) {
	if (trace->cursor + buf_len <= trace_limit) return false;
	hasReachedTraceLimit[thread_idx] = true;
	if (!isThreadFlushed) return true;
	
	// Trace limit has been reached, and flusher thread option is on
	doub_buf_trace_t* dbt = (doub_buf_trace_t*) trace;
	dbt_is_flushing:
	if (dbt->isFlushing) {
		// In this case we've already requested a flush but it
		// may not be finished yet
		waitFlushEnd(dbt);
	} 
	if (dbt->isFlushBufEmpty) {
		// Let's switch the buffers
		dbt->flush_buf = trace->buf;
		dbt->flush_buf_len = trace->cursor;
		trace->buf = (char*) malloc(sizeof(char) * trace_limit);
		trace->cursor = 0;
		dbt->isFlushBufEmpty = false;
		// We try to gain the privilege to talk with the semaphore
		// If the tracer is already on duty we just keep the old trace in a flush_buf pointer
		// and keep on with the analysis, otherwise we fire the flush
		if (PIN_MutexTryLock(&flusher_req_mutex)) {
			requestFlush(dbt, files[thread_idx]);
		}
		return false;
	} else  if (!dbt->isFlushBufEmpty) {
		// We have already prepared everything for the flush
		// and now we must obtain the privilege to talk with the flusher before proceding 
		// because we have finished the available space
		PIN_MutexLock(&flusher_req_mutex);
		requestFlush(dbt, files[thread_idx]);
		// Once fired the flusher we need to wait for it to finish
		// because we have nothing left for writing
		goto dbt_is_flushing;
	}
	return false;
}

inline void INS_Analysis(char* buf, UINT32 buf_len, THREADID thread_idx) {
	trace_t* trace = (trace_t*)PIN_GetThreadData(tls_key, thread_idx);
	// Trace limit guard
	if (traceLimitGuard(trace, buf_len, thread_idx)) return;

	if (isBuffered)
		recordInRawTrace(buf, buf_len, trace)
	else
		printRawTrace(files[thread_idx], buf, buf_len);
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
		recordInRawTrace(buf, buf_len, trace)
	else
		printRawTrace(files[thread_idx], buf, buf_len);
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

	INS_InsertCall(ins, IPOINT_BEFORE,
		(AFUNPTR)INS_Analysis,
		IARG_PTR,
		disassembled_ins,
		IARG_UINT32,
		disassembled_ins_len,
		IARG_THREAD_ID,
		IARG_END);


	if (INS_IsBranchOrCall(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR)INS_JumpAnalysis,
			IARG_BRANCH_TARGET_ADDR,
			IARG_BRANCH_TAKEN,
			IARG_THREAD_ID,
			IARG_END);
	}
}

void ThreadStart(THREADID thread_idx, CONTEXT* ctx, INT32 flags, VOID* v) {
	fprintf(stdout, "[*] Spawned thread %d\n", thread_idx);
	fflush(stdout);

	PIN_GetLock(&config_lock, thread_idx);
	/* Create output file */
	char filename[TRACE_NAME_LENGTH_LIMIT] = { 0 };
	sprintf(filename, "trace_%d.out", thread_idx);
	FILE* out = fopen(filename, "w+");
	fprintf(stdout, "[+] Created file %s\n", filename);
	fflush(stdout);

	/* Initialize a raw trace per thread */
	trace_t* trace;
	if (isThreadFlushed) {
		doub_buf_trace_t* dbt = (doub_buf_trace_t*) malloc(sizeof(doub_buf_trace_t));
		dbt->flush_buf = NULL; // We do not allocate space for this since this pointer will receive the trace's buf
		dbt->isFlushBufEmpty = true;
		trace = (trace_t*) dbt;
	} else
		trace = (trace_t*) malloc(sizeof(trace_t*));
	trace->buf = (char*) malloc(sizeof(char) * trace_limit);
	trace->cursor = 0;
	files[thread_idx] = out;

	traces[thread_idx] = trace;
	if (PIN_SetThreadData(tls_key, trace, thread_idx) == FALSE) {
		fprintf(stderr, "[x] PIN_SetThreadData failed");
		PIN_ExitProcess(1);
	}
	spawned_threads_no++;
	PIN_ReleaseLock(&config_lock);
}

void ThreadFini(THREADID thread_idx, const CONTEXT* ctx, INT32 code, VOID* v) {
	trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	fprintf(stdout, "[*] Finished thread %d, trace limit reached: %d\n", thread_idx, hasReachedTraceLimit[thread_idx]);
	if (isThreadFlushed) {
		doub_buf_trace_t* dbt = (doub_buf_trace_t*) trace;
		if (dbt->isFlushing) {
			fprintf(stdout, "[*] Flusher still on duty, waiting for it to finish\n");
			waitFlushEnd(dbt);
		}
		// If there is something else left in the main buf we save it now
		if (trace->cursor > 0) {
			printRawTrace(files[thread_idx], trace->buf, trace->cursor)
		}
	} else if (isBuffered)
		printAllRawTraces(files[thread_idx], trace);
	fprintf(stdout, "[*] Trace for thread #%d saved\n", thread_idx);
}

void Config() {
	isBuffered = KnobIsBuffered.Value();
	fprintf(stdout, "[*] Is Buffered? %d\n", isBuffered);

	isThreadFlushed = KnobIsThreadFlushed.Value();
	if (isThreadFlushed) isBuffered = true;
	fprintf(stdout, "[*] Is Thread flushed? %d\n", isThreadFlushed);

	trace_limit = KnobTraceLimit.Value() > 0 ? KnobTraceLimit.Value()*Mb : TRACE_LIMIT;
	fprintf(stdout, "[*] Trace limit %dMb\n", trace_limit/Mb);

}

void Usage() {
	fprintf(stderr, "--- PinCFGReconstructor ---\n");
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
		fprintf(stderr, "[x] An error occured while initiating PIN\n");
		return 0;
	}

	/* Prepare the Pintool */
	Config();

	/* Prepare TLS */
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY) {
		fprintf(stderr, "[x] Number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit\n");
		PIN_ExitProcess(1);
	}

	/* Prepare Locks and Mutexes */
	PIN_InitLock(&config_lock);
	PIN_MutexInit(&flusher_req_mutex);

	/* Spawn flusher thread if necessary */
	PIN_SpawnInternalThread(flusher::flusherThread, 0, 0, &flusher_uid);

	prog_name = argv[argc - 1];
	INS_AddInstrumentFunction(Ins, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
