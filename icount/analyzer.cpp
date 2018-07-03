#include <stdio.h>
#include <string.h>
#include <time.h>
#include "pin.H"
#include "analyzer.h"
#include "callbacks.h"
#include "flusher.h"

#include "loggers.h"
#include "utils.h"
#include "error_handlers.h"

TLS_KEY tls_key = INVALID_TLS_KEY;

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
time_t total_writed_intervals_creation_time;
time_t total_wxorx_check_time;

size_t spawned_threads_no;
size_t trace_size;
size_t total_flushes;
proc_info_t* proc_info;

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

// Online 
upx_info_t* upx_info;
bool isBinaryPacked = true;
FILE* upx_dump_file;
list<pair<ADDRINT, ADDRINT>> written_mem_intervals;
pair<ADDRINT, ADDRINT> main_img_memory(0, 0);
pair<ADDRINT, ADDRINT> text_sec_memory(0, 0);

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

void Img(IMG img, void* v) {
	if (!IMG_IsMainExecutable(img)) return;

	main_img_memory = make_pair(IMG_LowAddress(img), IMG_HighAddress(img));

	INFO("[+] Image %s loaded at 0x%08x\n", IMG_Name(img).c_str(), main_img_memory.first);
	// Find .text section address interval
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		string sec_name = SEC_Name(sec);
		if (sec_name == TEXT_SEC_NAME) {
			isBinaryPacked = false;
			text_sec_memory = make_pair(SEC_Address(sec), SEC_Address(sec) + SEC_Size(sec));
		}
	}
}

void Ins(INS ins, void* v) {
	ADDRINT ins_addr = INS_Address(ins);
	if (!IN_RANGE(ins_addr, main_img_memory.first, main_img_memory.second)) return;

	string disasm_ins_s = INS_Disassemble(ins);
	/* Allocate enough space to save
	- Disassembled instruction (n bytes)
	- INS_DELIMITER (1 byte)
	- 0 terminator (1 byte)
	*/
	uint32_t disasm_ins_len = strlen(disasm_ins_s.c_str()) + 2;
	char* disasm_ins = (char*) malloc(sizeof(char) * (disasm_ins_len));
	MALLOC_ERROR_HANDLER(disasm_ins, "[x] Not enough space to allocate disassembled_ins\n");
	disasm_ins[0] = INS_DELIMITER;
	disasm_ins[disasm_ins_len - 1] = '\0';
	strcpy(disasm_ins + 1, disasm_ins_s.c_str());
	if (isFirstIns) {
		isFirstIns = false;
		strcpy(disasm_ins, disasm_ins + 1);
	}

	INS_InsertCall(ins, IPOINT_BEFORE,
		(AFUNPTR) INS_EntryPoint,
				   IARG_INST_PTR,
				   IARG_THREAD_ID,
				   IARG_END);

	if (INS_IsBranchOrCall(ins)) {
		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR) INS_Analysis,
			IARG_PTR,
			disasm_ins,
			IARG_UINT32,
			disasm_ins_len,
			IARG_THREAD_ID,
			IARG_END);

		INS_InsertCall(ins, IPOINT_BEFORE,
			(AFUNPTR)INS_JumpAnalysis,
			IARG_BRANCH_TARGET_ADDR,
			IARG_BRANCH_TAKEN,
			IARG_THREAD_ID,
			IARG_END);
	}

	/* If we are in online mode, no .text section has been found and instruction
	in main img address */
	if (isOnline && isBinaryPacked && IN_RANGE(ins_addr, main_img_memory.first, main_img_memory.second)) {
		if (INS_Opcode(ins) == XED_ICLASS_PUSHAD ||
			INS_Opcode(ins) == XED_ICLASS_POPAD ||
			INS_Opcode(ins) == XED_ICLASS_JMP) {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR) INS_UPXEndAnalysis,
						   IARG_UINT32,
						   INS_Opcode(ins),
						   IARG_END);
		}
		

		if (INS_IsMemoryWrite(ins)) {
			INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR) INS_WriteAnalysis,
						   IARG_MEMORYWRITE_EA,
						   IARG_MEMORYWRITE_SIZE,
						   IARG_END);
		}
		/*if (upx_info->metJmp) {
		INS_InsertCall(ins, IPOINT_BEFORE,
				(AFUNPTR) INS_WXorX,
						   IARG_ADDRINT,
						   ins_addr,
						   IARG_PTR,
						   disasm_ins,
						   IARG_END);
		}*/
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

void dumpImg(IMG img) {
	char dump_file_name[MAX_FILENAME_LENGTH] = { 0 };
	sprintf(dump_file_name, "%s_img.dump", prog_name);
	FILE* dump_file = fopen(dump_file_name, "w+");
	size_t img_size = IMG_HighAddress(img) - IMG_LowAddress(img);
	char* dump = (char*) malloc(img_size);
	PIN_SafeCopy(dump, (void*) IMG_LowAddress(img), img_size);
	fwrite(dump, sizeof(char), img_size, dump_file);
	fclose(dump_file);
}

void dumpSections(IMG img) {
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		INFO("[*] Name: %s, from: 0x%08x to: 0x%08x\n", SEC_Name(sec).c_str(), SEC_Address(sec), SEC_Address(sec) + SEC_Size(sec))
		FILE* f = fopen((SEC_Name(sec) + ".dump").c_str(), "w+");
		char* sec_dump = (char*) malloc(SEC_Size(sec));
		PIN_SafeCopy(sec_dump, (void*) SEC_Address(sec), SEC_Size(sec));
		fwrite(sec_dump, sizeof(char), SEC_Size(sec), f);
		fclose(f);
	}
}

void dumpWrittenIntervals() {
	char dump_file_name[MAX_FILENAME_LENGTH] = { 0 };
	sprintf(dump_file_name, "%s_written_intervals.dump", prog_name);
	FILE* dump_file = fopen(dump_file_name, "w+");
	for each (pair<ADDRINT, ADDRINT> interval in written_mem_intervals) {
		//INFO("[+] Dumping from 0x%08x to 0x%08x\n", interval.first, interval.second);
		char* dump = (char*) malloc(interval.second - interval.first);
		PIN_SafeCopy(dump, (void*) interval.first, interval.second - interval.first);
		fprintf(dump_file, "%s", dump);
	}
	fclose(dump_file);
}

void PrepareForFini(void* v) {
	if (isOnline) {
		PIN_LockClient();
		IMG img = IMG_FindByAddress(main_img_memory.first);
		ERROR_HANDLER(!IMG_Valid(img), "[x] Invalid image to dump\n");
		PIN_UnlockClient();
		dumpImg(img);
		dumpSections(img);
		dumpWrittenIntervals();
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
		REPORT("[i] OEP found at 0x%08x\n", upx_info->OEP);
		REPORT("[i] Time spent to create intervals %d ms\n", total_writed_intervals_creation_time);
		REPORT("[i] Time spent to check WXorX rule %d ms\n", total_wxorx_check_time);
	}
	REPORT("[i] Entry point 0x%08x\n", proc_info->EP);
	REPORT("[i] Main thread time: %d ms\n", total_time);
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

	/* Config the Pintool */
	Config();

	// Proc info structure
	proc_info = (proc_info_t*) malloc(sizeof(proc_info_t));
	proc_info->EP = INVALID_ENTRY_POINT;

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

	/* Prepare structures for online mode */
	upx_dump_file = fopen("upx.dump", "w+");
	upx_info = (upx_info_t*) calloc(1, sizeof(upx_info_t));
	upx_info->OEP = INVALID_ENTRY_POINT;
	written_mem_intervals = list<pair<ADDRINT, ADDRINT>>();

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