#pragma once
#include <time.h>

/* Time utils */
#define START_STOPWATCH(tv) { tv = clock(); }
#define GET_STOPWATCH_LAP(tv) clock() - tv

/* Math utils */
#define IN_RANGE(a, b, c) (a >= b && a <= c)