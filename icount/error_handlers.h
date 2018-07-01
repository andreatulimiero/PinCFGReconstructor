#pragma once
#include "loggers.h"
#include "pin.H"

#define MALLOC_ERROR_HANDLER(buf, msg) {\
		if (buf == NULL) {\
			ERROR(msg);\
			PIN_ExitProcess(1);\
		}\
	}

#define ERROR_HANDLER(cond, msg) {\
		if (cond) {\
			ERROR(msg);\
			PIN_ExitProcess(1);\
		}\
	}