#include "pch.h"
#include "utils.h"

//IP转为字符串
CString IPn2a(DWORD IP)
{
    u_char* addr = (u_char*)&IP;
    CString IPa;
    IPa.Format(L"%03d.%03d.%03d.%03d", addr[3], addr[2], addr[1], addr[0]);
    return IPa;
}

//MAC转为字符串
CString MACn2a(BYTE* MAC)
{
    CString MACa;
    MACa.Format(L"%02x", MAC[0]);
    for (int i = 1; i < 6; i++)
        MACa.AppendFormat(L"-%02x", MAC[i]);
    return MACa.MakeUpper();
}

//比较两个MAC地址是否相等
bool cmpMAC(BYTE* a, BYTE* b)
{
	for (int i = 0; i < 6; i++)
		if (a[i] != b[i]) return false;
	return true;
}

//数据报捕获工作者线程
DWORD __stdcall captureThread(LPVOID s)
{
	CRouterDlg* p = (CRouterDlg*)s;
	int res = 0;
	pcap_pkthdr* header;
	u_char* pkt_data;
	while ((res = pcap_next_ex(p->adhandle, &header, (const u_char**)&pkt_data)) >= 0)    //利用pcap_next_ex()函数捕获数据包
	{
		if (res == 0) continue;
		WORD fmtp = ntohs(((FrameHeader_t*)pkt_data)->FrameType);
		if (fmtp == 0x0806)					//ARP协议
		{
			ARPFrame_t* ARPFrame = (ARPFrame_t*)pkt_data;
			WORD op = ntohs(ARPFrame->Operation);
			DWORD sendIP = ntohl(ARPFrame->SendIP);
			if (op == 0x0002)				//是ARP响应
			{
				for (int i = 0; i < 6; i++)
					p->IP2MAC[sendIP][i] = ARPFrame->SendHa[i];			//记录IP->MAC映射关系
				p->m_log.AppendFormat(L"ARP:%s->", IPn2a(sendIP));
				CString mac_str;
		
				mac_str.AppendFormat(L"MAC地址:%s", MACn2a(ARPFrame->SendHa));
				p->m_log.AppendFormat(L"%s\r\n", mac_str.GetBuffer());	//日志中显示IP->MAC映射关系
				AfxGetApp()->m_pMainWnd->PostMessage(WM_MYMESSAGE, 0, 0);
			}
		}
		else if (fmtp == 0x0800)			//IP协议
		{
			IPFrame_t* IPFrame = (IPFrame_t*)pkt_data;
			DWORD dstIP = ntohl(IPFrame->IPHeader.DstIP);
			//需要转发的IP数据报，目的MAC地址为本机接口MAC地址，目的IP地址不为本机IP地址
			if (cmpMAC(p->MAC, IPFrame->FrameHeader.DesMAC) && dstIP != p->IP1 && dstIP != p->IP2)
			{
				DWORD next;
				if (p->findNext(dstIP, &next))				//在路由表查找下一跳，未找到则丢弃IP数据报
				{
					Buffer_item* item = new Buffer_item;
					item->timer = new Timer;
					item->pkt_data = pkt_data;
					item->len = header->len;
					item->next = next;
					item->timer->setTimeOut(5000);			//定时器设置超时时间
					item->timer->startTimer();				//开启定时器
					p->buf->write(item);					//将含有IP数据报的记录存入缓冲区，等待发送者线程发送
				}
			}
		}
	}
	return 0;
}

//数据报转发工作者线程
DWORD __stdcall sendThread(LPVOID s)
{
	CRouterDlg* p = (CRouterDlg*)s;
	while (1)
	{
		Buffer_item* item = NULL;
		item = p->buf->read();				//从缓冲区中读取需要转发的IP数据报
		if (item == NULL) continue;
		if (item->timer->testTimeOut())		
		{
			delete item;					//如果超时，则将IP数据报丢弃
			continue;
		}
		//IP->MAC映射表中没有下一跳IP地址的映射关系
		if (p->IP2MAC.find(item->next) == p->IP2MAC.end())
		{
			//发送ARP请求，获取下一跳IP地址对应的MAC地址
			if ((item->next & p->mask1) == (p->IP1 & p->mask1))
				p->sendARP(item->next, p->IP1);
			else if ((item->next & p->mask2) == (p->IP2 & p->mask2))
				p->sendARP(item->next, p->IP2);
			p->buf->write(item);	//将数据报存入缓冲区
		}
		else	//IP->MAC映射表中有下一跳IP地址对应的MAC地址
		{
			u_char* pkt_data = item->pkt_data;
			IPFrame_t* IPFrame = (IPFrame_t*)pkt_data;
			if (IPFrame->IPHeader.TTL == 1)		//如果IP数据报的TTL=1
			{
				int e = p->sendICMP(pkt_data);	//向源IP地址发送ICMP超时报文
				delete item;					//丢弃IP数据报
				continue;
			}
			IPFrame->IPHeader.TTL--;			//将IP数据报TTL减1
			//重新计算检验和
			IPFrame->IPHeader.Checksum = 0;
			IPFrame->IPHeader.Checksum = calcChecksum((unsigned short*)&IPFrame->IPHeader, sizeof(IPHeader_t));
			DWORD src = ntohl(IPFrame->IPHeader.SrcIP);
			DWORD dst = ntohl(IPFrame->IPHeader.DstIP);
			for (int i = 0; i < 6; i++)
			{
				IPFrame->FrameHeader.SrcMAC[i] = p->MAC[i];						//以太帧的源MAC地址为本机接口MAC地址
				IPFrame->FrameHeader.DesMAC[i] = p->IP2MAC[item->next][i];		//目的MAC地址为下一跳MAC地址
			}
			pcap_sendpacket(p->adhandle, pkt_data, item->len);					//转发IP数据报
			CString src_str, dst_str, next_str;
			src_str = IPn2a(src);
			dst_str = IPn2a(dst);
			next_str = IPn2a(item->next);
			//在日志中显示数据报转发过程
			p->m_log.AppendFormat(L"IP:%s->%s%5Svia:%s\r\n", src_str.GetBuffer(), dst_str.GetBuffer(), " ", next_str.GetBuffer());
			AfxGetApp()->m_pMainWnd->PostMessage(WM_MYMESSAGE, 0, 0);
			delete item;
		}
	}
}

//计算检验和
WORD calcChecksum(unsigned short* IPBuf, int size)
{
	// 32位，延迟进位
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *IPBuf++;
		// 16位相加
		size -= 2;
	}
	if (size)
	{
		// 最后可能有单独8位
		cksum += *(unsigned char*)IPBuf;
	}
	// 将高16位进位加至低16位
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	// 取反
	return (unsigned short)(~cksum);
}

