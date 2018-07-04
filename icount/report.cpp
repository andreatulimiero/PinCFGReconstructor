#include <fstream>
#include "report.h"

#include "json.h"
#include "main.h"
#include "constants.h"

std::ofstream OutFile;

Json::Value report_j;

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

	OutFile.open("report.json");
	OutFile << report_j;
}