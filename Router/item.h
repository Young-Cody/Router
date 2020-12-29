#pragma once

//路由表项
struct item
{
	DWORD dst;		//目的网络
	DWORD mask;		//子网掩码
	DWORD next;		//下一跳
};
