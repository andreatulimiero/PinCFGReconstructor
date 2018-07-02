#include <stdio.h>
#include <string.h>
#include <map>
#include <time.h>
#include "pin.H"
#include "constants.h"
#include "loggers.h"
#include "utils.h"
#include "error_handlers.h"
#include "analyzer.h"
#include "flusher.h"

static TLS_KEY tls_key = INVALID_TLS_KEY;
PIN_LOCK pin_lock;
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
KNOB <BOOL> KnobFavorMainThread(KNOB_MODE_WRITEONCE, "pintool",
								"favor_main_thread", "false", "allocate a quarter of thread buffer for thread that are not 0");
KNOB <BOOL> KnobIsOnline(KNOB_MODE_WRITEONCE, "pintool",
						 "online", "false", "make an online analysis");

// Stats
time_t total_time;
time_t total_sync_time;
time_t total_wait_time;
time_t total_flusher_time;
time_t total_flusher_flushing_time;
time_t total_flushing_time;
size_t spawned_threads_no;
size_t trace_size;
size_t total_flushes;

// Configs
bool isBuffered;
bool isThreadFlushed;
bool isMainThreadFavored;
bool isOnline;
size_t trace_limit;
size_t thread_buffer_size;

bool isFirstIns = true;
const char* prog_name;

trace_t* traces[THREADS_MAX_NO];
FILE* files[THREADS_MAX_NO];
bool hasReachedTraceLimit[THREADS_MAX_NO];

ADDRINT img_address;
bool hasTextSection;
FILE* upx_dump_file;
pair<ADDRINT, ADDRINT> main_img_memory(0, 0);
pair<ADDRINT, ADDRINT> text_sec_memory(0, 0);

#define recordTraceInMemory(buf, buf_len, trace) {\
		memcpy(trace->buf + trace->cursor, buf, buf_len);\
		trace->cursor += buf_len;\
		trace_size += buf_len;\
	}

#define recordTraceToFile(f, buf, buf_len, trace) { flushTraceToFile(f, buf, buf_len); trace_size += buf_len; }

void waitFlushEnd(doub_buf_trace_t* dbt, THREADID thread_idx) {
	time_t tv;
	INFO("[*]{Thread %d} Waiting for flush to be finished\n", thread_idx);
	START_STOPWATCH(tv);
	PIN_SemaphoreWait(&dbt->end_flush_sem);
	total_wait_time += GET_STOPWATCH_LAP(tv);
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
	if (trace->cursor + buf_len <= trace->buf_size) return false;

	if (!isThreadFlushed) {
		time_t tv;
		INFO("[*] Thread buffer limit reached, flushing\n");
		if (!thread_idx) START_STOPWATCH(tv);
		flushTraceToFile(files[thread_idx], trace->buf, trace->cursor);
		if (!thread_idx) total_flushing_time += GET_STOPWATCH_LAP(tv);
		trace->cursor = 0;
	} else {
		time_t tv;
		if (!thread_idx)
			START_STOPWATCH(tv);
		// Thread buffer limit has been reached, and flusher thread option is on
		doub_buf_trace_t* dbt = (doub_buf_trace_t*) trace;
		if (dbt->isFlushBufEmpty) {
			// Let's switch the buffers
			dbt->flush_buf = trace->buf;
			dbt->flush_buf_len = trace->cursor;
			trace->buf = (char*) malloc(sizeof(char) * trace->buf_size);
			MALLOC_ERROR_HANDLER(trace->buf, "[x] Not enough space to allocate another buffer for the trace\n");
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
		if (!thread_idx)
			total_sync_time += GET_STOPWATCH_LAP(tv);
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
	MALLOC_ERROR_HANDLER(buf, "[x] Not enough space to allocate the buf for the INS_JumpAnalysis\n");
	buf[0] = '\n';
	buf[1] = '@';
	buf[buf_len - 1] = '\0';
	// Consider removing this sprintf since it is very slow
	sprintf(buf + 2, "%x", target_branch);

	if (isBuffered)
		recordTraceInMemory(buf, buf_len, trace)
	else
		recordTraceToFile(files[thread_idx], buf, buf_len, trace);

	// Since this is created each time the instruction is encountered we can delete this
	free(buf);
}

inline void INS_UPX(ADDRINT mem_write_target) {
	if (mem_write_target >= main_img_memory.first && mem_write_target <= main_img_memory.second) {
		INFO("[*] Function writing in image address\n");
	}
}

void Img(IMG img, void* v) {
	if (!strstr(IMG_Name(img).c_str(), prog_name)) return;

	main_img_memory = make_pair(IMG_LowAddress(img), IMG_LowAddress(img) + IMG_SizeMapped(img));
	img_address = IMG_LowAddress(img);

	// Dump main IMG
	/*char dump_file_name[256] = { 0 };
	sprintf(dump_file_name, "%s.dump", prog_name);
	FILE* dump_file = fopen(dump_file_name, "w+");
	INFO("[+] Dumping %s IMG\n", prog_name);
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
			RTN_Open(rtn);
			for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
				fprintf(dump_file, "%s\n", INS_Disassemble(ins).c_str());
			}
			RTN_Close(rtn);
		}
	}
	fflush(dump_file);
	fclose(dump_file);*/

	INFO("[+] Image %s loaded at 0x%x\n", IMG_Name(img).c_str(), IMG_StartAddress(img));
	// Find .text section address interval
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		string sec_name = SEC_Name(sec);
		if (sec_name == TEXT_SEC_NAME) {
			hasTextSection = true;
			text_sec_memory = make_pair(SEC_Address(sec), SEC_Address(sec) + SEC_Size(sec));
		}
	}
	if (!hasTextSection) {
		upx_dump_file = fopen("upx.dump", "w+");
	}
}

void Ins(INS ins, void* v) {
	string disassembled_ins_s = INS_Disassemble(ins);
	/* Allocate enough space to save
	- Disassembled instruction (n bytes)
	- INS_DELIMITER (1 byte)
	- 0 terminator (1 byte)
	*/
	uint32_t disassembled_ins_len = strlen(disassembled_ins_s.c_str()) + 2;
	char* disassembled_ins = (char*) malloc(sizeof(char) * (disassembled_ins_len));
	MALLOC_ERROR_HANDLER(disassembled_ins, "[x] Not enough space to allocate disassembled_ins\n");
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

	ADDRINT ins_addr = INS_Address(ins);
	/*If we are in online mode, no .text section has been found and instruction
	in main img address*/
	if (isOnline && !hasTextSection && (ins_addr >= main_img_memory.first && ins_addr <= main_img_memory.second)) {
		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR) INS_UPX,
			IARG_ADDRINT,
			IARG_END);
	}
}

void ThreadStart(THREADID thread_idx, CONTEXT* ctx, INT32 flags, VOID* v) {
	INFO("[*] Spawned thread %d with OS_THREADID %d\n", thread_idx,  PIN_GetTid());

	PIN_GetLock(&pin_lock, thread_idx);
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

	if (isMainThreadFavored) {
		if (thread_idx == 0)	trace->buf_size = thread_buffer_size;
		else					trace->buf_size = thread_buffer_size/MAIN_THREAD_FAVOR_FACTOR;
	} else 
		trace->buf_size = thread_buffer_size;

	trace->buf = (char*) malloc(sizeof(char) * trace->buf_size);
	MALLOC_ERROR_HANDLER(trace->buf, "[x] Not enough space to allocate the buffer\n");
	trace->cursor = 0;
	files[thread_idx] = out;

	traces[thread_idx] = trace;
	if (PIN_SetThreadData(tls_key, trace, thread_idx) == FALSE) {
		ERROR("[x] PIN_SetThreadData failed\n");
		PIN_ExitProcess(1);
	}
	spawned_threads_no++;
	PIN_ReleaseLock(&pin_lock);
}

void ThreadFini(THREADID thread_idx, const CONTEXT* ctx, INT32 code, VOID* v) {
	trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	REPORT("[*]{Thread %d} Ended, trace limit reached: %d\n", thread_idx, hasReachedTraceLimit[thread_idx]);
	if (isThreadFlushed) {
		doub_buf_trace_t* dbt = (doub_buf_trace_t*) trace;
		if (dbt->isFlushing) {
			INFO("[*]{Thread %d} Flusher still on duty, waiting for it to finish\n", thread_idx);
			waitFlushEnd(dbt, thread_idx);
		}
	} 
	// If there is something else left in the main buf we save it now
	if (trace->cursor > 0) {
		INFO("[*]{Thread %d} Flushing remaining %d Mb\n", thread_idx, trace->cursor / Mb);
		flushTraceToFile(files[thread_idx], trace->buf, trace->cursor)
	}
	fclose(files[thread_idx]);

	total_time += GET_STOPWATCH_LAP(total_time);
	INFO("[*]{Thread %d} Trace saved\n", thread_idx);
}

void Config() {
	isBuffered = KnobIsBuffered.Value();
	INFO("[*] Is Buffered? %d\n", isBuffered);

	isThreadFlushed = KnobIsThreadFlushed.Value();
	if (isThreadFlushed) isBuffered = true;
	INFO("[*] Is Thread flushed? %d\n", isThreadFlushed);

	isMainThreadFavored = KnobFavorMainThread.Value();
	INFO("[*] Is main thread favored? %d\n", isMainThreadFavored);

	trace_limit = KnobTraceLimit.Value() > 0 ? KnobTraceLimit.Value()*Mb : TRACE_LIMIT;
	INFO("[*] Trace limit: %dMb\n", trace_limit/Mb);

	thread_buffer_size = KnobThreadBufferSize.Value() > 0 ? KnobThreadBufferSize.Value()*Mb : THREAD_BUFFER_SIZE;
	INFO("[*] Thread buffer size: %dMb\n", thread_buffer_size/Mb);

	isOnline = KnobIsOnline.Value();
	INFO("[*] Is online? %d\n", isOnline);
}

void Usage() {
	ERROR("--- PinCFGReconstructor ---\n");
	ERROR((KNOB_BASE::StringKnobSummary() + "\n").c_str());
}

void ApplicationStartFunction(void* v) {
	START_STOPWATCH(total_time);
}

void PrepareForFini(void* v) {
	if (isOnline) {
		PIN_LockClient();
		IMG img = IMG_FindByAddress(img_address);
		ERROR_HANDLER(!IMG_Valid(img), "[x] Invalid image to dump\n");
		PIN_UnlockClient();
		char dump_file_name[256] = { 0 };
		sprintf(dump_file_name, "%s_fini.dump", prog_name);
		FILE* dump_file = fopen(dump_file_name, "w+");
		INFO("[*] Requesting a dump of the main IMG %s\n", IMG_Name(img).c_str());
		char sec_f = 0, rtn_f = 0, ins_f = 0;
		for (SEC sec= IMG_SecHead(img);	SEC_Valid(sec); sec = SEC_Next(sec)) {
			if (SEC_Name(sec) != TEXT_SEC_NAME) continue;
			for (RTN rtn = SEC_RtnHead(sec); RTN_Valid(rtn); rtn = RTN_Next(rtn)) {
				RTN_Open(rtn);
				for (INS ins = RTN_InsHead(rtn); INS_Valid(ins); ins = INS_Next(ins)) {
					ADDRINT ins_addr = INS_Address(ins);
					if (ins_addr >= main_img_memory.first && ins_addr <= main_img_memory.second)
						fprintf(dump_file, "%s\n", INS_Disassemble(ins).c_str());
				}
				RTN_Close(rtn);
			}
		}
		fflush(dump_file);
		fclose(dump_file);
	} else 
		if (isThreadFlushed) {
			INFO("[*] Waiting for flusher to terminate\n");
			flusher::isPoisoned = true;
			PIN_SemaphoreSet(&flusher::flusher_sem);
			PIN_WaitForThreadTermination(flusher_uid, PIN_INFINITE_TIMEOUT, NULL);
		}
}

void Fini(INT32 code, VOID *v) {
	//REPORT("=======================\n");
	//REPORT("Trace finished\n");
	if (isThreadFlushed) {
		REPORT("Time spent to sync with flusher: %d ms\n", total_sync_time);
		REPORT("Time spent waiting for flusher: %d ms\n", total_wait_time);
		REPORT("Time the flusher was flushing: %d ms\n", total_flusher_flushing_time);
		REPORT("Average time per flush: %d ms\n", total_flusher_flushing_time / total_flushes);
		REPORT("Time the flusher was running: %d ms\n", total_flusher_time);
	} else if (isBuffered) {
		REPORT("Time spent for flushing: %d ms\n", total_flushing_time);
		REPORT("Average time per flush: %d ms\n", total_flushing_time / total_flushes);
	}
	REPORT("Main thread time: %d ms\n", total_time);
	//REPORT("Size: %d Mb\n", trace_size/Mb);
	//REPORT("Threads spawned: %d\n", spawned_threads_no);
	REPORT("=======================\n");
}

char* getProgName(char** argv) {
	while (strcmp(*argv, "--")) {
		argv++;
	}
	char* prog_name = *(argv+1);
	char* back_slash = strrchr(prog_name, '\\');
	if (back_slash)
		return back_slash + 1;
	return prog_name;
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
	PIN_InitLock(&pin_lock);
	PIN_MutexInit(&flusher_req_mutex);
	PIN_SemaphoreInit(&flusher_ready_sem);
	// Flusher
	PIN_SemaphoreInit(&flusher::flusher_sem);
	PIN_SemaphoreSet(&flusher::flusher_ready_sem);


	/* Spawn flusher thread if necessary */
	if (isThreadFlushed)
		PIN_SpawnInternalThread(flusher::flusherThread, 0, 0, &flusher_uid);

	prog_name = getProgName(argv);
	INS_AddInstrumentFunction(Ins, 0);
	IMG_AddInstrumentFunction(Img, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddApplicationStartFunction(ApplicationStartFunction, 0);
	PIN_AddPrepareForFiniFunction(PrepareForFini, 0);
	PIN_AddFiniFunction(Fini, 0);

	/*INFO("[*] trace_t size: %d\n", sizeof(trace_t));
	INFO("[*] doub_buf_trace_t size: %d\n", sizeof(doub_buf_trace_t));*/

	PIN_StartProgram();
	return 0;
}