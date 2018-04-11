#include "CapturePacket.h"
#define IPTOSBUFFERS 12
void Capture::ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;
	char ipv6addr[128];
	/* �豸��(Name) */
	cout<<d->name<< endl;
	/* �豸����(Description) */
	if (d->description)
		cout<<"\tDescription: "<<d->description<<endl;

	/* Loopback Address*/
	cout<<"\tLoopback: "<<((d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no") <<endl;

	/* IP addresses */
	for (a = d->addresses; a != nullptr; a = a->next) {
		cout<<"\tAddress Family: #"<<a->addr->sa_family<<endl;
		switch (a->addr->sa_family)
		{
		case AF_INET:
			cout <<"\tAddress Family Name: AF_INET\n";
			if (a->addr)
				cout <<"\tAddress: " <<iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr)<<endl;
			if (a->netmask)
				cout <<"\tNetmask:" <<iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr)<<endl;
			if (a->broadaddr)
				cout << "\tBroadcast Address:" <<iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr)<<endl;
			if (a->dstaddr)
				cout <<"\tDestination Address:" <<iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr)<<endl;
			break;
		case AF_INET6:
			cout <<"\tAddress Family Name: AF_INET6\n";
			if (a->addr)
				cout <<"\tAddress:" <<ip6tos(a->addr, ipv6addr, sizeof(ipv6addr))<<endl;
			break;

		default:
			cout <<"\tAddress Family Name: Unknown\n";
			break;
		}
	}
	cout <<"\n";
}

char * Capture::iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;
	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

char* Capture::ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif
	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;
	return address;
}

void Capture::ListAdapters()
{
	pcap_if_t *alldevs;	// ���ڴ洢���������ͷָ��
	pcap_if_t *d;	// ���嵥���豸��
	pcap_t *adhandle;
	int numOfAdapters = 0;	// ��¼�����ĸ���
	char *AdaName;
	char errBuf[PCAP_ERRBUF_SIZE]; // ��¼������Ϣ������
	int chooseDe = 0;	//��ѡ����豸
	int i = 0;	//ѭ���ı�������
	char errbuf[PCAP_ERRBUF_SIZE + 1];
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	/* ѭ���г���Ӧ������������ */
	for (d = alldevs; d; d = d->next)
	{
		if (d->description)
		{
			numOfAdapters++;
			ifprint(d);
		}
		else
		{
			cout << "No description available\n";
		}
	}
	cout << "choose one Device(Numbers is"<< numOfAdapters <<")by No.\n";
	cin >> chooseDe;
	/* ����ѡ��ĳ����˷�Χ���� */
	if (chooseDe <1 || chooseDe >numOfAdapters)
	{
		cout << "Intefaces is out of range.\n";
		pcap_freealldevs(alldevs);
		return;
	}
	/* ��ת��ѡ�е������� */
	for (d = alldevs, i = 0; i < chooseDe; d = d->next, i++)
	{	}

	if ((adhandle = pcap_open_live(d->name,          // �豸��
		65536,            // 65535��֤�ܲ��񵽲�ͬ������·���ϵ�ÿ�����ݰ���ȫ������
		NULL,
		1000,             // ��ȡ��ʱʱ��           
		errbuf            // ���󻺳��
		)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* �ͷ��豸�б� */
		pcap_freealldevs(alldevs);
		return;
	}
	if (d->addresses != NULL)
	{

	}

	printf("\nlistening on %s...\n", d->description);
	pcap_freealldevs(alldevs);
	pcap_loop(adhandle, 0, packet_handler, NULL);
}

void Capture::packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	/* ��ʱ���ת���ɿ�ʶ��ĸ�ʽ */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);
	printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
}