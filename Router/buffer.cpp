#include "pch.h"
#include "buffer.h"

Buffer::Buffer(int size)
{
	this->size = size;
	front = rear = 0;
	buf = new Buffer_item*[size];
	memset(buf, NULL, sizeof(Buffer_item*) * size);
	mutex = CreateSemaphore(NULL, 1, 1, NULL);
}

Buffer::~Buffer()
{
	delete[]buf;
	CloseHandle(mutex);
}

void Buffer::write(Buffer_item* item)
{
	WaitForSingleObject(mutex, INFINITE);
	if (rear >= front + size)
	{
		ReleaseSemaphore(mutex, 1, NULL);
		return;
	}
	buf[++rear % size] = item;
	ReleaseSemaphore(mutex, 1, NULL);
}

Buffer_item* Buffer::read()
{
	WaitForSingleObject(mutex, INFINITE);
	if (front == rear)
	{
		ReleaseSemaphore(mutex, 1, NULL);
		return NULL;
	}
	Buffer_item *ret = buf[++front % size];
	buf[front % size] = NULL;
	ReleaseSemaphore(mutex, 1, NULL);
	return ret;
}
