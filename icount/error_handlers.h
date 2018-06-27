#pragma once
#include "loggers.h"
#include "pin.H"

#define MALLOC_ERROR_HANDLER(buf, msg) {\
		if (buf == NULL) {\
			ERROR(msg);\
			PIN_ExitApplication(1);\
		}\
	}