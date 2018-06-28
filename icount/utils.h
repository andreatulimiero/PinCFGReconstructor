#pragma once
#include <time.h>

#define START_STOPWATCH(tv) { tv = clock(); }
#define GET_STOPWATCH_LAP(tv) clock() - tv