#include "pch.h"
#include "utils.h"

//IPתΪ�ַ���
CString IPn2a(DWORD IP)
{
    u_char* addr = (u_char*)&IP;
    CString IPa;
    IPa.Format(L"%03d.%03d.%03d.%03d", addr[3], addr[2], addr[1], addr[0]);
    return IPa;
}

//MACתΪ�ַ���
CString MACn2a(BYTE* MAC)
{
    CString MACa;
    MACa.Format(L"%02x", MAC[0]);
    for (int i = 1; i < 6; i++)
        MACa.AppendFormat(L"-%02x", MAC[i]);
    return MACa.MakeUpper();
}

//�Ƚ�����MAC��ַ�Ƿ����
bool cmpMAC(BYTE* a, BYTE* b)
{
	for (int i = 0; i < 6; i++)
		if (a[i] != b[i]) return false;
	return true;
}

//���ݱ����������߳�
DWORD __stdcall captureThread(LPVOID s)
{
	CRouterDlg* p = (CRouterDlg*)s;
	int res = 0;
	pcap_pkthdr* header;
	u_char* pkt_data;
	while ((res = pcap_next_ex(p->adhandle, &header, (const u_char**)&pkt_data)) >= 0)    //����pcap_next_ex()�����������ݰ�
	{
		if (res == 0) continue;
		WORD fmtp = ntohs(((FrameHeader_t*)pkt_data)->FrameType);
		if (fmtp == 0x0806)					//ARPЭ��
		{
			ARPFrame_t* ARPFrame = (ARPFrame_t*)pkt_data;
			WORD op = ntohs(ARPFrame->Operation);
			DWORD sendIP = ntohl(ARPFrame->SendIP);
			if (op == 0x0002)				//��ARP��Ӧ
			{
				for (int i = 0; i < 6; i++)
					p->IP2MAC[sendIP][i] = ARPFrame->SendHa[i];			//��¼IP->MACӳ���ϵ
				p->m_log.AppendFormat(L"ARP:%s->", IPn2a(sendIP));
				CString mac_str;
		
				mac_str.AppendFormat(L"MAC��ַ:%s", MACn2a(ARPFrame->SendHa));
				p->m_log.AppendFormat(L"%s\r\n", mac_str.GetBuffer());	//��־����ʾIP->MACӳ���ϵ
				AfxGetApp()->m_pMainWnd->PostMessage(WM_MYMESSAGE, 0, 0);
			}
		}
		else if (fmtp == 0x0800)			//IPЭ��
		{
			IPFrame_t* IPFrame = (IPFrame_t*)pkt_data;
			DWORD dstIP = ntohl(IPFrame->IPHeader.DstIP);
			//��Ҫת����IP���ݱ���Ŀ��MAC��ַΪ�����ӿ�MAC��ַ��Ŀ��IP��ַ��Ϊ����IP��ַ
			if (cmpMAC(p->MAC, IPFrame->FrameHeader.DesMAC) && dstIP != p->IP1 && dstIP != p->IP2)
			{
				DWORD next;
				if (p->findNext(dstIP, &next))				//��·�ɱ������һ����δ�ҵ�����IP���ݱ�
				{
					Buffer_item* item = new Buffer_item;
					item->timer = new Timer;
					item->pkt_data = pkt_data;
					item->len = header->len;
					item->next = next;
					item->timer->setTimeOut(5000);			//��ʱ�����ó�ʱʱ��
					item->timer->startTimer();				//������ʱ��
					p->buf->write(item);					//������IP���ݱ��ļ�¼���뻺�������ȴ��������̷߳���
				}
			}
		}
	}
	return 0;
}

//���ݱ�ת���������߳�
DWORD __stdcall sendThread(LPVOID s)
{
	CRouterDlg* p = (CRouterDlg*)s;
	while (1)
	{
		Buffer_item* item = NULL;
		item = p->buf->read();				//�ӻ������ж�ȡ��Ҫת����IP���ݱ�
		if (item == NULL) continue;
		if (item->timer->testTimeOut())		
		{
			delete item;					//�����ʱ����IP���ݱ�����
			continue;
		}
		//IP->MACӳ�����û����һ��IP��ַ��ӳ���ϵ
		if (p->IP2MAC.find(item->next) == p->IP2MAC.end())
		{
			//����ARP���󣬻�ȡ��һ��IP��ַ��Ӧ��MAC��ַ
			if ((item->next & p->mask1) == (p->IP1 & p->mask1))
				p->sendARP(item->next, p->IP1);
			else if ((item->next & p->mask2) == (p->IP2 & p->mask2))
				p->sendARP(item->next, p->IP2);
			p->buf->write(item);	//�����ݱ����뻺����
		}
		else	//IP->MACӳ���������һ��IP��ַ��Ӧ��MAC��ַ
		{
			u_char* pkt_data = item->pkt_data;
			IPFrame_t* IPFrame = (IPFrame_t*)pkt_data;
			if (IPFrame->IPHeader.TTL == 1)		//���IP���ݱ���TTL=1
			{
				int e = p->sendICMP(pkt_data);	//��ԴIP��ַ����ICMP��ʱ����
				delete item;					//����IP���ݱ�
				continue;
			}
			IPFrame->IPHeader.TTL--;			//��IP���ݱ�TTL��1
			//���¼�������
			IPFrame->IPHeader.Checksum = 0;
			IPFrame->IPHeader.Checksum = calcChecksum((unsigned short*)&IPFrame->IPHeader, sizeof(IPHeader_t));
			DWORD src = ntohl(IPFrame->IPHeader.SrcIP);
			DWORD dst = ntohl(IPFrame->IPHeader.DstIP);
			for (int i = 0; i < 6; i++)
			{
				IPFrame->FrameHeader.SrcMAC[i] = p->MAC[i];						//��̫֡��ԴMAC��ַΪ�����ӿ�MAC��ַ
				IPFrame->FrameHeader.DesMAC[i] = p->IP2MAC[item->next][i];		//Ŀ��MAC��ַΪ��һ��MAC��ַ
			}
			pcap_sendpacket(p->adhandle, pkt_data, item->len);					//ת��IP���ݱ�
			CString src_str, dst_str, next_str;
			src_str = IPn2a(src);
			dst_str = IPn2a(dst);
			next_str = IPn2a(item->next);
			//����־����ʾ���ݱ�ת������
			p->m_log.AppendFormat(L"IP:%s->%s%5Svia:%s\r\n", src_str.GetBuffer(), dst_str.GetBuffer(), " ", next_str.GetBuffer());
			AfxGetApp()->m_pMainWnd->PostMessage(WM_MYMESSAGE, 0, 0);
			delete item;
		}
	}
}

//��������
WORD calcChecksum(unsigned short* IPBuf, int size)
{
	// 32λ���ӳٽ�λ
	unsigned long cksum = 0;
	while (size > 1)
	{
		cksum += *IPBuf++;
		// 16λ���
		size -= 2;
	}
	if (size)
	{
		// �������е���8λ
		cksum += *(unsigned char*)IPBuf;
	}
	// ����16λ��λ������16λ
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	// ȡ��
	return (unsigned short)(~cksum);
}

