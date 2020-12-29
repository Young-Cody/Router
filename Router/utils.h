#pragma once
#include"RouterDlg.h"
#include<afx.h>

CString IPn2a(DWORD);
CString MACn2a(BYTE*);
bool cmpMAC(BYTE*, BYTE*);
DWORD WINAPI captureThread(LPVOID);
DWORD WINAPI sendThread(LPVOID);
WORD calcChecksum(unsigned short* IPBuf, int size);
BYTE* getHostMAC(DWORD, DWORD);
