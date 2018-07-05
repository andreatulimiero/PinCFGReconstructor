#include <list>

#include "callbacks.h"
#include "main.h"
#include "constants.h"
#include "loggers.h"
#include "utils.h"
#include "error_handlers.h"
#include <iostream>

void INS_EntryPoint(ADDRINT ip, THREADID thread_idx) {
	if (IN_RANGE(ip, main_img_memory.first, main_img_memory.second) &&
		proc_info->EP == INVALID_ENTRY_POINT) {

		proc_info->EP = ip;
		/* Allocate enough space in order to save:
		- @ char (1 byte)
		- address in hex format (sizeof(ADDRINT) * 2 bytes) for ip
		- 0 terminator (1 byte)*/
		size_t buf_len = sizeof(ADDRINT) * 2 + 2;
		char* buf = (char*) malloc(buf_len);
		sprintf(buf, "@%08x\0", ip);

		trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
		// Trace limit guard
		if (traceLimitGuard(trace, buf_len, thread_idx)) return;

		if (isBuffered)
			recordTraceInMemory(buf, buf_len, trace)
		else
			recordTraceToFile(files[thread_idx], buf, buf_len, trace);
	}
}

void INS_Analysis(char* buf, UINT32 buf_len, THREADID thread_idx) {
	trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	// Trace limit guard
	if (traceLimitGuard(trace, buf_len, thread_idx)) return;

	if (isBuffered)
		recordTraceInMemory(buf, buf_len, trace)
	else
		recordTraceToFile(files[thread_idx], buf, buf_len, trace);
}

void INS_JumpAnalysis(ADDRINT ins_end, ADDRINT target_branch, INT32 taken, THREADID thread_idx) {
	if (!taken) return;
	trace_t* trace = (trace_t*) PIN_GetThreadData(tls_key, thread_idx);
	/* Allocate enough space in order to save:
	- @ char (1 byte)
	- address in hex format (sizeof(ADDRINT) * 2) * 2 bytes for ip and target
	- \n delimiter (1 byte)
	- 0 terminator (1 byte)*/
	size_t buf_len = (sizeof(ADDRINT) * 4 + 3);
	// Trace limit guard
	if (traceLimitGuard(trace, buf_len, thread_idx)) return;

	char* buf = (char*) malloc(sizeof(char) * buf_len);
	MALLOC_ERROR_HANDLER(buf, "[x] Not enough space to allocate the buf for the INS_JumpAnalysis\n");
	// Consider removing this sprintf since it is very slow
	sprintf(buf, "\n%08x@%08x\0", ins_end, target_branch);

	if (isBuffered)
		recordTraceInMemory(buf, buf_len, trace)
	else
		recordTraceToFile(files[thread_idx], buf, buf_len, trace);

	/* Since this buf is either flushed or copied in memory we can free it */
	free(buf);
}

void INS_WriteAnalysis(ADDRINT at, ADDRINT size) {
	if (upx_info->metJmp) return;
	time_t tv;
	START_STOPWATCH(tv);
	bool hasFoundRange = false;
	for each (pair<ADDRINT, ADDRINT> interval in written_mem_intervals) {
		// Check if low address is in range
		if (IN_RANGE(at, interval.first, interval.second)) {
			// If high address is bigger than second interval enlarge it
			if ((at + size) > interval.second) interval.second = at + size;
			hasFoundRange = true;
		}

		// Check if high address is in range
		if (IN_RANGE(at + size, interval.first, interval.second)) {
			// If low address is smaller than first interval enlarge it
			if (at < interval.first) interval.first = at;
			hasFoundRange = true;
		}
	}

	// If no range has been found, let's create a new one
	if (!hasFoundRange)
		written_mem_intervals.push_front(make_pair(at, at + size));
	total_writed_intervals_creation_time += GET_STOPWATCH_LAP(tv);
}

void INS_UPXEndAnalysis(OPCODE opcode) {
	if (!upx_info->metJmp) {
		if (opcode == XED_ICLASS_PUSHAD)
			upx_info->metPushad = true;
		else if (upx_info->metPushad && opcode == XED_ICLASS_POPAD)
			upx_info->metPopad = true;
		else if (upx_info->metPopad && opcode == XED_ICLASS_JMP)
			upx_info->metJmp = true;
	}
}

void INS_WXorX(ADDRINT at, const char* disasm_ins) {
	time_t tv;
	START_STOPWATCH(tv);
	for each (pair<ADDRINT, ADDRINT> interval in written_mem_intervals) {
		if (IN_RANGE(at, interval.first, interval.second)) {
			if (upx_info->OEP == INVALID_ENTRY_POINT)
				upx_info->OEP = at;
			fprintf(upx_dump_file, "%s", disasm_ins);
		}
	}
	total_wxorx_check_time += GET_STOPWATCH_LAP(tv);
}
