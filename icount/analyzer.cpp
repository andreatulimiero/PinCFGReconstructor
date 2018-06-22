#include "pin.H"
#include <stdio.h>
#include <string.h>
#include "types.h"

static TLS_KEY tls_key = INVALID_TLS_KEY;
PIN_LOCK pin_lock;

/** Custom options for our PIN tool **/
KNOB <BOOL> KnobIsBuffered(KNOB_MODE_WRITEONCE, "pintool",
	"buffered", "false", "whether or not the trace is buffered");
KNOB <size_t> KnobTraceLimit(KNOB_MODE_WRITEONCE, "pintool",
	"trace_limit", "0", "size of the trace limit");

static size_t spawned_threads_no;

bool isBuffered;
size_t trace_limit;

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

#define printRawTrace(f, buf, buf_len) {\
	for (size_t i = 0; i < buf_len; i++) { fputc(buf[i], f); }\
	}

inline void INS_Analysis(char* buf, UINT32 buf_len, THREADID thread_idx) {
	trace_t* trace = (trace_t*)PIN_GetThreadData(tls_key, thread_idx);
	// Trace limit guard
	if (trace->cursor + buf_len >= trace_limit) {
		hasReachedTraceLimit[thread_idx] = true;
		return;
	}

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
	if (trace->cursor + buf_len >= trace_limit) {
		hasReachedTraceLimit[thread_idx] = true;
		return;
	}

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

	PIN_GetLock(&pin_lock, thread_idx);
	/* Create output file */
	char filename[TRACE_NAME_LENGTH_LIMIT] = { 0 };
	sprintf(filename, "trace_%d.out", thread_idx);
	FILE* out = fopen(filename, "w+");
	fprintf(stdout, "[+] Created file %s\n", filename);
	fflush(stdout);

	/* Initialize a raw trace per thread */
	trace_t* trace = (trace_t*)malloc(sizeof(trace_t*));
	trace->buf = (char*)malloc(sizeof(char) * trace_limit);
	trace->cursor = 0;
	files[thread_idx] = out;

	traces[thread_idx] = trace;
	if (PIN_SetThreadData(tls_key, trace, thread_idx) == FALSE) {
		fprintf(stderr, "[x] PIN_SetThreadData failed");
		PIN_ExitProcess(1);
	}
	spawned_threads_no++;
	PIN_ReleaseLock(&pin_lock);
}

void ThreadFini(THREADID thread_idx, const CONTEXT* ctx, INT32 code, VOID* v) {
	fprintf(stdout, "[*] Finished thread %d, trace limit reached: %d\n", thread_idx, hasReachedTraceLimit[thread_idx]);
	if (isBuffered)
		printAllRawTraces(files[thread_idx], (trace_t*) PIN_GetThreadData(tls_key, thread_idx));
	fprintf(stdout, "[*] Trace for thread #%d saved\n", thread_idx);
}

void Config() {
	isBuffered = KnobIsBuffered.Value();
	fprintf(stdout, "[*] Is Buffered? %d\n", isBuffered);

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

	/* Prepare Lock */
	PIN_InitLock(&pin_lock);

	prog_name = argv[argc - 1];
	INS_AddInstrumentFunction(Ins, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
