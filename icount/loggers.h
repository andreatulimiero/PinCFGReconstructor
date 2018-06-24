#pragma once

#define INFO_LEVEL 1
#define DEBUG_LEVEL 1

#if INFO_LEVEL
	#define INFO(format, ...) { fprintf(stdout, format, __VA_ARGS__); }
#else
	#define INFO(format, ...) { do {} while(0); }
#endif

#if DEBUG_LEVEL
	#define DEBUG(format, ...) { fprintf(stdout, format, __VA_ARGS__); fflush(stdout); }
#else
	#define DEBUG(format, ...) { do {} while(0); }
#endif

#define ERROR(format, ...) { fprintf(stderr, format, __VA_ARGS__); }