#include "Vfs.h"
#include "Time.h"

ULONG GetSystemTimeStamp(VOID)
{
	LARGE_INTEGER Frequency;
	LARGE_INTEGER SystemTime;
	LARGE_INTEGER TickCount;
	ULONGLONG SecElapsed,SecStarted;

	QueryPerformanceFrequency(&Frequency);
	QueryPerformanceCounter(&TickCount);
	GetSystemTimeAsFileTime((LPFILETIME)&SystemTime);

	// Calculating number of seconds elapsed since the system started
	SecElapsed = (ULONGLONG)TickCount.QuadPart / (ULONGLONG)Frequency.QuadPart;

	// Calculating number of seconds elapsed since January 1, 1601 (UTC) before the system started
	SecStarted = (ULONGLONG)SystemTime.QuadPart / 10000000 - SecElapsed;

	// Calculating number of 3-day intervals elapsed since January 1, 1601 (UTC) before the system started
	SecStarted /= (3600 * 24 * 3);

	return((ULONG)(SecStarted));
}
ULONG MyRandom(PULONG pSeed)
{
	return(*pSeed = 1664525 * (*pSeed) + 1013904223);
}