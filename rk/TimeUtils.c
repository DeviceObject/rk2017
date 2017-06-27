#include "rk.h"
#include "TimeUtils.h"

//这个函数返回一个“滴答”表示的多少100纳秒
VOID MyGetTickCount_100N()
{
	LARGE_INTEGER    tick_count;
	ULONG            inc;

	inc = KeQueryTimeIncrement();
	KeQueryTickCount(&tick_count);
	tick_count.QuadPart /= 10000;
	tick_count.QuadPart *= inc;
}

//KeQuerySystemTime表示的多少100纳秒
VOID MyGetCurrentTime_100N()
{
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS   TimeFiled;

	// 这里得到的其实是格林威治时间
	KeQuerySystemTime(&CurrentTime);
	// 转换成本地时间
	ExSystemTimeToLocalTime(&CurrentTime, &LocalTime);
	// 把时间转换为容易理解的形式
	RtlTimeToTimeFields(&LocalTime, &TimeFiled);
}

//返回多少秒
LONG MyGetTickCount_S()
{
	LARGE_INTEGER    tick_count;
	ULONG            inc;

	inc = KeQueryTimeIncrement();
	KeQueryTickCount(&tick_count);

	tick_count.QuadPart *= inc;
	tick_count.QuadPart /= 10000;
	tick_count.QuadPart /= 1000;

	return tick_count.LowPart;
}

//返回多少秒
LONG MyGetCurrentTime_S()
{
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LocalTime;

	KeQuerySystemTime(&CurrentTime);
	ExSystemTimeToLocalTime(&CurrentTime, &LocalTime);
	LocalTime.QuadPart /= 10000;
	LocalTime.QuadPart /= 1000;

	return LocalTime.LowPart;
}