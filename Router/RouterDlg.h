#include"item.h"
#include<vector>
#include<map>
#include"pcap.h"
#include"protocol.h"
#include"buffer.h"
#include <windows.h>
#include<time.h>
// RouterDlg.h: 头文件
//

#pragma once
#define WM_MYMESSAGE						WM_USER + 1
// CRouterDlg 对话框
class CRouterDlg : public CDialogEx
{
// 构造
public:
	CRouterDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ROUTER_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedAdd();
	afx_msg void OnBnClickedDel();
	afx_msg void OnBnClickedUpdt();
	CIPAddressCtrl m_dst;
	CIPAddressCtrl m_mask;
	CIPAddressCtrl m_next;
	std::vector<item> items;
	BYTE MAC[6];
	DWORD IP1;
	DWORD IP2;
	DWORD mask1;
	DWORD mask2;
	CString m_log;
	CListBox m_rtb;
	Buffer *buf;
	pcap_t* adhandle;
	pcap_if_t* alldevs;
	std::map<DWORD, BYTE[6]>IP2MAC;
	void getAddr(CIPAddressCtrl* addrctrl, DWORD* addrl, CString* addrstr);
	int sendARP(DWORD requestIP, DWORD sendIP);
	int sendICMP(u_char* pkt_data);
	bool findNext(DWORD dstIP, DWORD *next);
	BYTE* getHostMAC(DWORD requestIP, DWORD send);
	afx_msg void OnLbnSelchangeRtb();
protected:
	afx_msg LRESULT OnMymessage(WPARAM wParam, LPARAM lParam);
};
