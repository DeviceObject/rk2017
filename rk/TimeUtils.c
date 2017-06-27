#include "rk.h"
#include "TimeUtils.h"

//�����������һ�����δ𡱱�ʾ�Ķ���100����
VOID MyGetTickCount_100N()
{
	LARGE_INTEGER    tick_count;
	ULONG            inc;

	inc = KeQueryTimeIncrement();
	KeQueryTickCount(&tick_count);
	tick_count.QuadPart /= 10000;
	tick_count.QuadPart *= inc;
}

//KeQuerySystemTime��ʾ�Ķ���100����
VOID MyGetCurrentTime_100N()
{
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER LocalTime;
	TIME_FIELDS   TimeFiled;

	// ����õ�����ʵ�Ǹ�������ʱ��
	KeQuerySystemTime(&CurrentTime);
	// ת���ɱ���ʱ��
	ExSystemTimeToLocalTime(&CurrentTime, &LocalTime);
	// ��ʱ��ת��Ϊ����������ʽ
	RtlTimeToTimeFields(&LocalTime, &TimeFiled);
}

//���ض�����
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

//���ض�����
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