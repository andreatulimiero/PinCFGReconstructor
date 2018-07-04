#include <fstream>
#include "report.h"

#include "json.h"
#include "main.h"
#include "constants.h"

std::ofstream ReportFile;
std::ofstream PerformanceFile;

Json::Value report_j;
Json::Value performance_j;

void reportImage(IMG img) {
	string img_name = IMG_Name(img);
	ADDRINT low_address = IMG_LowAddress(img);
	ADDRINT high_address = IMG_HighAddress(img);
	report_j["images"][img_name]["low_address"] = low_address;
	report_j["images"][img_name]["high_address"] = high_address;
}

void reportMainImage(IMG img) {
	string img_name = IMG_Name(img);
	report_j["main_image"] = img_name;
}

void makeReport() {
	if (isBinaryPacked) {
		// TODO: This has to be found dinamically
		report_j["text_section"] = "UPX1";
		report_j["entry_point"] = upx_info->OEP;
	} else {
		report_j["text_section"] = TEXT_SEC_NAME;
		report_j["entry_point"] = proc_info->EP;
	}

	if (performance_tag != "") {
		if (isThreadFlushed) {
			performance_j["mode"] = "thread_flushed";
			performance_j["sync_with_flusher"] = total_sync_time;
			performance_j["waiting_for_flusher"] = total_wait_time;
			performance_j["flusher_flushing"] = total_flusher_flushing_time;
			performance_j["flusher_running"] = total_flusher_time;
			performance_j["average_flush_time"] = (int) (total_flusher_flushing_time / total_flushes);
		} else if (isBuffered) {
			performance_j["mode"] = "buffered";
			performance_j["flushing_time"] = total_flushing_time;
			performance_j["average_flush_time"] = (int) (total_flushing_time / total_flushes);
		} else {
			performance_j["mode"] = "flushed";
		}
		performance_j["main_thread_time"] = total_time;
		performance_j["trace_size"] = trace_size / Mb;

		PerformanceFile.open(performance_tag.c_str());
		PerformanceFile << performance_j;
	}

	ReportFile.open("report.json");
	ReportFile << report_j;
}