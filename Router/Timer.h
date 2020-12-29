#ifndef TIMER_H
#define TIMER_H
#include<Windows.h>
#include<iostream>
using namespace std;

//计时器
struct Timer{
    Timer();                    //计时器初始化
    void startTimer();          //计时器开始计时
    void setTimer();            //得到当前click数
    void stopTimer();           //计时器停止计时
    double getDiff();           //得到时间差
    bool testTimeOut();         //检测是否超时
    void setTimeOut(double);    //设置超时时间
    bool isStart;               //计时器是否开始
    double timeout;             //超时时间，单位ms
    LARGE_INTEGER timer_start, timer_end, f;
};

#endif // !TIMER_H