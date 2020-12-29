
// RouterDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "Router.h"
#include "RouterDlg.h"
#include"utils.h"
#include "afxdialogex.h"
#include"buffer.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CRouterDlg 对话框



CRouterDlg::CRouterDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_ROUTER_DIALOG, pParent)
	, m_log(_T(""))
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CRouterDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_LOG, m_log);
	DDX_Control(pDX, IDC_RTB, m_rtb);
	DDX_Control(pDX, IDC_DST, m_dst);
	DDX_Control(pDX, IDC_MASK, m_mask);
	DDX_Control(pDX, IDC_NEXT, m_next);
}

BEGIN_MESSAGE_MAP(CRouterDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_ADD, &CRouterDlg::OnBnClickedAdd)
	ON_BN_CLICKED(IDC_DEL, &CRouterDlg::OnBnClickedDel)
	ON_BN_CLICKED(IDC_UPDT, &CRouterDlg::OnBnClickedUpdt)
	ON_LBN_SELCHANGE(IDC_RTB, &CRouterDlg::OnLbnSelchangeRtb)
	ON_MESSAGE(WM_MYMESSAGE, &CRouterDlg::OnMymessage)
END_MESSAGE_MAP()


// CRouterDlg 消息处理程序

BOOL CRouterDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	ShowWindow(SW_MINIMIZE);

	// TODO: 在此添加额外的初始化代码
	DWORD initaddr = 0;
	m_dst.SetAddress(initaddr);
	m_mask.SetAddress(initaddr);
	m_next.SetAddress(initaddr);
	items.resize(128);
	char errbuf[PCAP_ERRBUF_SIZE];
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		if (MessageBox(L"获取本机网络接口失败",L"错误",MB_OK) == IDOK)
			PostQuitMessage(0);
	}
	m_log.AppendFormat(L"%S\r\n", alldevs->description);
	//将MAC地址和IP地址设置为虚拟地址，获取本机MAC地址
	for (int i = 0; i < 6; i++)
		MAC[i] = 0x66;
	IP1 = ntohl(inet_addr("112.112.112.112"));

	if ((adhandle = pcap_open(alldevs->name, 100, PCAP_OPENFLAG_PROMISCUOUS, 20, NULL, errbuf)) == NULL)	//pcap_open函数返回NULL，调用出错
	{
		if (MessageBox(L"打开接口失败", L"错误", MB_OK) == IDOK)
			PostQuitMessage(0);
	}

	pcap_addr* a = alldevs->addresses;

	DWORD requestIP = ntohl(((sockaddr_in*)a->addr)->sin_addr.S_un.S_addr);
	BYTE *tmp = getHostMAC(requestIP, IP1);
	if (tmp == NULL)
	{
		if (MessageBox(L"获取接口MAC地址失败", L"错误", MB_OK) == IDOK)
			PostQuitMessage(0);
	}
	else
	{
		//在日志中显示本机MAC地址
		CString mac_str;
		for (int i = 0; i < 6; i++)
			MAC[i] = tmp[i];
		mac_str.Format(L"MAC地址:");
		mac_str += MACn2a(MAC);
		m_log.AppendFormat(L"%s\r\n", mac_str.GetBuffer());
	}
	//在路由表中显示可以直接投递的路由表项
	CString ip_str, mask_str;
	CString display;
	DWORD dst;
	IP1 = ntohl(((sockaddr_in*)a->addr)->sin_addr.S_un.S_addr);
	mask1 = ntohl(((sockaddr_in*)a->netmask)->sin_addr.S_un.S_addr);
	dst = IP1 & mask1;
	ip_str = IPn2a(dst);
	mask_str = IPn2a(mask1);
	display.Format(L"%s%20S%s%27S直接投递", ip_str.GetBuffer(), " ", mask_str.GetBuffer(), " ");
	m_rtb.AddString(display);
	items[0].dst = dst;
	items[0].mask = mask1;
	items[0].next = 0;

	a = a->next;
	IP2 = ntohl(((sockaddr_in*)a->addr)->sin_addr.S_un.S_addr);
	mask2 = ntohl(((sockaddr_in*)a->netmask)->sin_addr.S_un.S_addr);
	dst = IP2 & mask2;
	ip_str = IPn2a(dst);
	mask_str = IPn2a(mask2);
	display.Format(L"%s%20S%s%27S直接投递", ip_str.GetBuffer(), " ", mask_str.GetBuffer(), " ");
	m_rtb.AddString(display);
	items[1].dst = dst;
	items[1].mask = mask2;
	items[1].next = 0;

	//在日志中显示本机接口的两个IP地址
	in_addr inaddr1, inaddr2;
	inaddr1.S_un.S_addr = htonl(IP1);
	inaddr2.S_un.S_addr = htonl(IP2);
	m_log.AppendFormat(L"IP地址:%S\r\n", inet_ntoa(inaddr1));
	m_log.AppendFormat(L"IP地址:%S\r\n", inet_ntoa(inaddr2));

	//初始化缓冲区
	buf = new Buffer(1024);
	//创建数据报捕获工作者线程
	CreateThread(NULL, 0, captureThread, LPVOID(this), 0, NULL);
	//创建数据报转发工作者线程
	CreateThread(NULL, 0, sendThread, LPVOID(this), 0, NULL);

	UpdateData(FALSE);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CRouterDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CRouterDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CRouterDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

//添加路由表项
void CRouterDlg::OnBnClickedAdd()
{
	// TODO: 在此添加控件通知处理程序代码
	DWORD addrl;
	int idx = m_rtb.GetCount();
	CString addr_dst;
	CString addr_mask;
	CString addr_next;
	//获取目的网络
	getAddr(&m_dst, &addrl, &addr_dst);
	items[idx].dst = addrl;
	//获取下一跳
	getAddr(&m_next, &addrl, &addr_next);
	items[idx].next = addrl;
	//获取子网掩码
	getAddr(&m_mask, &addrl, &addr_mask);
	items[idx].mask = addrl;

	//在程序界面中显示新添加的路由表项
	CString display = addr_dst;
	display.AppendFormat(L"%20S%s", " ", addr_mask.GetBuffer());
	display.AppendFormat(L"%20S%s", " ", addr_next.GetBuffer());

	m_rtb.AddString(display);
}

//删除路由表项
void CRouterDlg::OnBnClickedDel()
{
	// TODO: 在此添加控件通知处理程序代码
	int idx = m_rtb.GetCurSel();
	if (idx == LB_ERR)
	{
		MessageBox(L"请选择要删除的路由表项");
		return;
	}
	if (idx <= 1)
	{
		MessageBox(L"不能删除直接投递的路由表项");
		return;
	}

	//删除选中的路由表项
	items.erase(items.begin() + idx);
	m_rtb.DeleteString(idx);
}

//修改路由表项
void CRouterDlg::OnBnClickedUpdt()
{
	// TODO: 在此添加控件通知处理程序代码
	int idx = m_rtb.GetCurSel();
	if (idx == LB_ERR)
	{
		MessageBox(L"请选择要修改的路由表项");
		return;
	}
	if (idx <= 1)
	{
		MessageBox(L"不能修改直接投递的路由表项");
		return;
	}
	DWORD addrl;
	CString addr_dst;
	CString addr_mask;
	CString addr_next;

	//获取路由表项中的值
	getAddr(&m_dst, &addrl, &addr_dst);
	items[idx].dst = addrl;
	getAddr(&m_next, &addrl, &addr_next);
	items[idx].next = addrl;
	getAddr(&m_mask, &addrl, &addr_mask);
	items[idx].mask = addrl;

	//在程序界面中显示修改后的路由表项
	CString display = addr_dst;
	display.AppendFormat(L"%20S%s", " ", addr_mask.GetBuffer());
	display.AppendFormat(L"%20S%s", " ", addr_next.GetBuffer());
	m_rtb.DeleteString(idx);
	m_rtb.InsertString(idx, display);
}

//获取IP控件中的IP地址字符串
void CRouterDlg::getAddr(CIPAddressCtrl* addrctrl, DWORD* addrl, CString* addrstr)
{
	BYTE addrb[4];
	addrctrl->GetAddress(addrb[0], addrb[1], addrb[2], addrb[3]);
	addrctrl->GetAddress(*addrl);
	addrstr->Format(L"%03d.%03d.%03d.%03d", addrb[0], addrb[1], addrb[2], addrb[3]);
}

//获取本机MAC地址
BYTE* CRouterDlg::getHostMAC(DWORD requestIP, DWORD sendIP)
{
	if (sendARP(requestIP, sendIP) == -1) return NULL;    //发送ARP请求
	int res = 0;
	pcap_pkthdr* header;
	const u_char* pkt_data;
	time_t start = time(NULL);
	time_t end;
	while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) > 0)    //利用pcap_next_ex()函数捕获数据包
	{
		if (res == 0)
			continue;
		ARPFrame_t* ARPFrame = (ARPFrame_t*)pkt_data;
		if (ntohs(ARPFrame->FrameHeader.FrameType) == 0x0806)    //如果是ARP帧
		{
			if (ntohs(ARPFrame->Operation) == 0x0002 && ntohl(ARPFrame->SendIP) == requestIP)  //是请求IP地址的ARP响应，则返回所对应的MAC地址
				return ARPFrame->SendHa;
		}
		end = time(NULL);
		if (difftime(end, start) > 1) return NULL;    //获取超时
	}
}

//发送ARP协议
int CRouterDlg::sendARP(DWORD requestIP, DWORD sendIP)
{
	ARPFrame_t ARPFrame;

	for (int i = 0; i < 6; i++)
	{
		ARPFrame.FrameHeader.DesMAC[i] = 0xff;			//目的MAC地址为广播地址0xffffffffffff
		ARPFrame.FrameHeader.SrcMAC[i] = MAC[i];		//源MAC地址为接口MAC地址，获取本机MAC地址时，为虚拟地址0x666666666666
		ARPFrame.SendHa[i] = MAC[i];					//本机网卡MAC地址
		ARPFrame.RecvHa[i] = 0;							//设置为0
	}

	ARPFrame.FrameHeader.FrameType = htons(0x0806);		//帧类型为ARP

	ARPFrame.HardwareType = htons(0x0001);				//硬件类型为以太网
	ARPFrame.ProtocolType = htons(0x0800);				//协议类型为IP
	ARPFrame.HLen = 6;									//硬件地址长度为6
	ARPFrame.PLen = 4;									//协议地址长度为4
	ARPFrame.Operation = htons(0x0001);					//操作为ARP请求
	ARPFrame.SendIP = htonl(sendIP);					//本机网卡绑定的IP地址
	ARPFrame.RecvIP = htonl(requestIP);					//请求的IP地址
	if (pcap_sendpacket(adhandle, (u_char*)&ARPFrame, sizeof(ARPFrame_t)) != 0)
		return -1;
	return 0;
}

//发送ICMP超时报文
int CRouterDlg::sendICMP(u_char* pkt_data)
{
	u_char ICMP[134];					//134 = 14(以太) + 20(IP) + 8(ICMP) + 20(IP) + 8(ICMP) + 64(0)
	memset(ICMP, 0, sizeof(ICMP));
	IPFrame_t* IPFrame = (IPFrame_t*)pkt_data;

	FrameHeader_t* FrameHeader = (FrameHeader_t*)ICMP;
	IPHeader_t* IPHeader = (IPHeader_t*)(ICMP + 14);
	ICMPHeader_t* ICMPHeader = (ICMPHeader_t*)(ICMP + 34);

	//将源MAC和目的MAC地址互换
	memcpy(FrameHeader->DesMAC, IPFrame->FrameHeader.SrcMAC, 6);
	memcpy(FrameHeader->SrcMAC, IPFrame->FrameHeader.DesMAC, 6);
	FrameHeader->FrameType = htons(0x0800);

	memcpy(IPHeader, &IPFrame->IPHeader, 20);
	IPHeader->TotalLen = htons(120);
	IPHeader->TTL = 128;
	IPHeader->Protocol = 1;
	//源IP地址为路由器IP地址
	IPHeader->SrcIP = htonl(IP2);
	//目的IP地址为超时IP数据报的源IP地址
	IPHeader->DstIP = IPFrame->IPHeader.SrcIP;
	IPHeader->Checksum = 0;
	IPHeader->Checksum = calcChecksum((unsigned short*)IPHeader, 20);

	ICMPHeader->Code = 0;		//ICMP超时报文的code为0
	ICMPHeader->Type = 11;		//ICMO超时报文的type为11
	ICMPHeader->Id = 0;
	ICMPHeader->Sequence = 0;
	//计算ICMP超时报文的检验和
	ICMPHeader->CheckSum = 0;
	ICMPHeader->CheckSum = calcChecksum((unsigned short*)ICMPHeader, 8);

	//将超时的IP数据报复制进ICMP报文
	memcpy(ICMP + 42, pkt_data + 14, ntohs(IPFrame->IPHeader.TotalLen));

	//发送ICMP数据报
	return pcap_sendpacket(adhandle, ICMP, 134);
}

bool CRouterDlg::findNext(DWORD dstIP, DWORD* next)
{
	DWORD max = 0;
	next = NULL;
	for (int i = 0; i < m_rtb.GetCount(); i++)
	{
		//如果目的IP和掩码相与后与目的网络相等
		if ((items[i].mask & dstIP) == items[i].dst)
		{
			//直接投递
			if (i <= 1)
			{
				max = items[i].mask;
				*next = dstIP;
				break;
			}
			//掩码比当前最大的掩码大
			else if (items[i].mask > max)
			{
				//更新当前最大的掩码和下一跳
				max = items[i].mask;
				*next = items[i].next;
			}
		}
	}
	//如果找到下一跳返回true，否则返回false
	if (next != NULL) return true;
	return false;
}

void CRouterDlg::OnLbnSelchangeRtb()
{
	// TODO: 在此添加控件通知处理程序代码
	int idx = m_rtb.GetCurSel();
	if (idx == LB_ERR) return;
	m_dst.SetAddress(items[idx].dst);
	m_next.SetAddress(items[idx].next);
	m_mask.SetAddress(items[idx].mask);
}


afx_msg LRESULT CRouterDlg::OnMymessage(WPARAM wParam, LPARAM lParam)
{
	UpdateData(FALSE);
	return 0;
}
