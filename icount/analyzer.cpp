#include "pin.H"
#include <stdio.h>
#include <string.h>
#include "types.h"

static TLS_KEY tls_key = INVALID_TLS_KEY;
PIN_LOCK pin_lock;

/** Custom options for our PIN tool **/
//KNOB<string> KnobBufferedOption(KNOB_MODE_WRITEONCE, "pintool",
							//"buffered", false, "<buffered>");

static size_t spawned_threads_no;

bool isBuffered = true;
bool isFirstIns = true;
const char* prog_name;

short unsigned int hasDone = 0;

trace_t* traces[THREADS_MAX_NO];
FILE* files[THREADS_MAX_NO];

//#define recordInRawTrace(buf, buf_len, trace) do {\
		memcpy(trace->buf + trace->cursor, buf, buf_len);\
		trace->cursor += buf_len;\
	} while (0);
void recordInRawTrace(const char* buf, size_t buf_len, trace_t* trace) {
	memcpy(trace->buf + trace->cursor, buf, buf_len);
	trace->cursor += buf_len;
}

void printAllRawTrace(FILE* f) {
	size_t trace_no = 0;
	trace_t* trace = traces[trace_no];
	while (trace != NULL) {
		for (size_t i = 0; i < trace->cursor; i++) {
			fputc(trace->buf[i], f);
		}
		trace = traces[++trace_no];
	}
}

void printRawTrace(FILE* f, const char* buf, size_t buf_len) {
	for (size_t i = 0; i < buf_len; i++) {
		fputc(buf[i], f);
	}
}

void INS_Analysis(char* disassembled_ins, UINT32 disassembled_ins_len, THREADID thread_idx) {
	trace_t* trace = (trace_t*)PIN_GetThreadData(tls_key, thread_idx);
	// Trace limit guard
	if (trace->cursor + disassembled_ins_len >= TRACE_LIMIT) return;
	if (isBuffered) {
		recordInRawTrace(disassembled_ins, disassembled_ins_len, trace);
	} else {
		printRawTrace(files[thread_idx], disassembled_ins, disassembled_ins_len);
	}
}

void INS_JumpAnalysis(ADDRINT target_branch, INT32 taken, THREADID thread_idx) {
	if (!taken) return;
	trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	/* Allocate enough space in order to save:
	- @ char (1 byte)
	- address in hex format (sizeof(ADDRINT) * 2 bytes) + '0x' prefix (2 bytes)
	- \n delimiter (1 byte)
	- 0 terminator (1 byte)
	*/
	size_t buf_len = (sizeof(ADDRINT) * 2 + 5);
	// Trace limit guard
	if (trace->cursor + buf_len >= TRACE_LIMIT) return;
	char* buf = (char*)calloc(1, sizeof(char) * buf_len);
	buf[0] = '\n';
	buf[1] = '@';
	sprintf(buf + 2, "%x", target_branch);
	if (isBuffered)
		recordInRawTrace(buf, buf_len, trace);
	else
		printRawTrace(files[thread_idx], buf, buf_len);
}

void Trace(TRACE trace, void* v) {
	// Let's whitelist the instrumented program only
	RTN rtn = TRACE_Rtn(trace);
	if (RTN_Valid(rtn)) {
		SEC sec = RTN_Sec(rtn);
		if (SEC_Valid(sec)) {
			IMG img = SEC_Img(sec);
			if (IMG_Valid(img)) {
				if (!strstr(IMG_Name(img).c_str(), prog_name)) {
					//fprintf(stdout, "[-] Ignoring %s\n", IMG_Name(img).c_str());
					return;
				}
				//fprintf(stdout, "[+] Instrumenting %s <= %s\n", IMG_Name(img).c_str(), prog_name);
				//fflush(stdout);
			} else return;
		} else return;
	} else return;

	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
		for (INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)) {
			string disassembled_ins_s = INS_Disassemble(ins);
			/* Allocate enough space to save
			- Disassembled instruction (n bytes)
			- INS_DELIMITER (1 byte)
			- 0 terminator (1 byte)
			*/
			uint32_t disassembled_ins_len = strlen(disassembled_ins_s.c_str()) + 2;
			char* disassembled_ins = (char*)calloc(1, sizeof(char) * (disassembled_ins_len));
			disassembled_ins[0] = INS_DELIMITER;
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
	}
}

void ThreadStart(THREADID thread_idx, CONTEXT* ctx, INT32 flags, VOID* v) {
	fprintf(stdout, "[*] Spawned thread %d\n", thread_idx);
	fflush(stdout);

	/* Create output file */
	char filename[TRACE_NAME_LENGTH_LIMIT] = { 0 };
	sprintf(filename, "trace_%d.out", thread_idx);
	FILE* out = fopen(filename, "w+");
	fprintf(stdout, "[+] Created file %s => %x\n", filename, out);
	fflush(stdout);

	/* Initialize a raw trace per thread */
	PIN_GetLock(&pin_lock, thread_idx);
	trace_t* trace = (trace_t*)malloc(sizeof(trace_t*));
	trace->buf = (char*)malloc(sizeof(char) * RAW_TRACE_BUF_SIZE);
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
	fprintf(stdout, "[*] Finished thread %d\n", thread_idx);
	if (isBuffered)
		printAllRawTrace(files[thread_idx]);
	fprintf(stdout, "[+] Trace for thread #%d saved\n", thread_idx);
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

	/* Prepare TLS */
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY) {
		fprintf(stderr, "[x] Number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit\n");
		PIN_ExitProcess(1);
	}

	/* Prepare Lock */
	PIN_InitLock(&pin_lock);

	prog_name = argv[argc - 1];
	TRACE_AddInstrumentFunction(Trace, 0);

	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();
	return 0;
}
