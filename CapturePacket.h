#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <winsock2.h>
#include <iostream>
#include <pcap.h>  
#pragma	comment( lib, "ws2_32.lib")// 库文件  
#pragma	comment( lib, "wpcap.lib" )// 库文件 
#pragma	comment( lib, "Packet.lib" )// 库文件 
using namespace std;

class Capture
{
public:
	void ifprint(pcap_if_t *d);
	char *iptos(u_long in);
	char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);
	void ListAdapters();
	void static packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
private:
	pcap_if_t *alldevs;
	pcap_if_t *d;
	char errbuf[PCAP_ERRBUF_SIZE];
	/* 4字节的IP地址 */
	typedef struct ip_address 
	{
		u_char byte1;
		u_char byte2;
		u_char byte3;
		u_char byte4;
	}ip_address;

	/* IPv4 首部 */
	typedef struct ip_header {
		u_char  ver_ihl;        // 版本 (4 bits) + 首部长度 (4 bits)
		u_char  tos;            // 服务类型(Type of service) 
		u_short tlen;           // 总长(Total length) 
		u_short identification; // 标识(Identification)
		u_short flags_fo;       // 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
		u_char  ttl;            // 存活时间(Time to live)
		u_char  proto;          // 协议(Protocol)
		u_short crc;            // 首部校验和(Header checksum)
		ip_address  saddr;      // 源地址(Source address)
		ip_address  daddr;      // 目的地址(Destination address)
		u_int   op_pad;         // 选项与填充(Option + Padding)
	}ip_header;


};

