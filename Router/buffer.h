#pragma once
#include"protocol.h"
#include"Timer.h"

struct Buffer_item {
	u_char* pkt_data;
	Timer *timer;
	int len;
	DWORD next;
};

//缓冲区
class Buffer {
public:
	Buffer(int size);
	~Buffer();
	void write(Buffer_item *item);	//相缓冲区中写入数据
	Buffer_item* read();			//从缓冲区中读取数据

private:
	HANDLE mutex;					//互斥信号量
	Buffer_item** buf;				//缓冲区
	int size;						//缓冲区大小
	int front, rear;				//首部和尾部
};
