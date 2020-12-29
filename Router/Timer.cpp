#include"Timer.h"
#include"pch.h"
//计时器初始化
Timer::Timer()
{
    timeout = 0;
    QueryPerformanceFrequency(&f);
    isStart = false;
}

//计时器开始计时
void Timer::startTimer()
{
    isStart = true;
    setTimer();
}

//得到当前click数
void Timer::setTimer()
{
    QueryPerformanceCounter(&timer_start);
}

//计时器停止计时
void Timer::stopTimer()
{
    isStart = false;
}

//得到时间差
double Timer::getDiff()
{
    QueryPerformanceCounter(&timer_end);
    return ((timer_end.QuadPart - timer_start.QuadPart) * 1000.0 / f.QuadPart);
}

//检测是否超时
bool Timer::testTimeOut()
{
    return getDiff() > timeout;
}

//设置超时时间
void Timer::setTimeOut(double time)
{
    timeout = time;
}