#include <iostream>

#include "pin.H"
#include "main.h"
#include "report.h"
#include "loggers.h"

void dumpImg(IMG img) {
	char dump_file_name[MAX_FILENAME_LENGTH] = { 0 };
	sprintf(dump_file_name, "%s_img.dump", prog_name);
	FILE* dump_file = fopen(dump_file_name, "w+");
	size_t img_size = main_img_memory.second - main_img_memory.first;
	char* dump = (char*) malloc(img_size);
	PIN_SafeCopy(dump, (void*) main_img_memory.first, img_size);
	fwrite(dump, sizeof(char), img_size, dump_file);
	fclose(dump_file);
}

void dumpSections(IMG img) {
	for (SEC sec = IMG_SecHead(img); SEC_Valid(sec); sec = SEC_Next(sec)) {
		INFO("[*] Name: %s, from: 0x%08x to: 0x%08x\n", SEC_Name(sec).c_str(), SEC_Address(sec), SEC_Address(sec) + SEC_Size(sec));
		FILE* f = fopen((SEC_Name(sec) + ".dump").c_str(), "w+");
		char* sec_dump = (char*) malloc(SEC_Size(sec));
		PIN_SafeCopy(sec_dump, (void*) SEC_Address(sec), SEC_Size(sec));
		INFO("[+] Dumped %d/%d\n", fwrite(sec_dump, sizeof(char), SEC_Size(sec), f), SEC_Size(sec));
		fclose(f);

		report_j["sections"][SEC_Name(sec)]["address"] = SEC_Address(sec);
		report_j["sections"][SEC_Name(sec)]["size"] = SEC_Size(sec);
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