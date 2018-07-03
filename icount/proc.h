#pragma once

typedef struct proc_info_s {
	ADDRINT EP;
} proc_info_t;

typedef struct upx_info_s {
	bool metPushad;
	bool metPopad;
	bool metJmp;
	ADDRINT OEP;
} upx_info_t;