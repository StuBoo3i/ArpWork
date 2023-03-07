#include "ArpWork.h"
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <iostream>
#include <sstream>
#include <string> 

using namespace std;
#pragma comment(lib,"Iphlpapi.lib")

ArpWork::ArpWork(QWidget *parent)
    : QMainWindow(parent)
{
    ui.setupUi(this);
}

ArpWork::~ArpWork()
{}

void ArpWork::send()
{
    QString HostIP,GateIP,NetName = "";
    HostIP = ui.lineEdit->text();
    GateIP= ui.lineEdit_2->text();
    NetName = ui.lineEdit_3->text();
    ui.lineEdit->setText(NetName);
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
