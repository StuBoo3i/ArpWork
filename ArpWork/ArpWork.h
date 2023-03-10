#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <QtWidgets/QMainWindow>
#include <WinSock2.h>
#include <Iphlpapi.h>
#include <iostream>
#include <sstream>
#include <string> 
#include "ui_ArpWork.h"
#include "pcap.h"
#pragma comment(lib,"Iphlpapi.lib")
#pragma comment(lib,"wpcap")

//MAC��ַ
struct mac_address {
    u_char byte[6];
};

struct eth_head {
    mac_address destMAC;    	//Ŀ��MAC��ַ 6�ֽ�  
    mac_address sourceMAC;      //ԴMAC��ַ 6�ֽ�  
    u_short     type;           //֡����, 0x0806��ARP֡������ֵ
};
#pragma pack(1)
struct arp_head
{
    unsigned short  hardwareType;       //Ӳ������
    unsigned short  protocolType;       //Э������
    unsigned char   hardwareAddLen;     //Ӳ����ַ����
    unsigned char   protocolAddLen;     //Э���ַ����
    unsigned short  op;                 //op����������
    mac_address     sourceMAC;          //���ͷ�MAC��ַ
    unsigned long   sourceIP;           //���ͷ�IP��ַ
    mac_address     destMAC;            //Ŀ��MAC��ַ
    unsigned long   destIP;             //Ŀ��IP��ַ
};


struct arp_packet
{
    eth_head apt_eth_head;
    arp_head apt_arp_head;
};

class ArpWork : public QMainWindow
{
    Q_OBJECT

public:
    ArpWork(QWidget *parent = nullptr);
    ~ArpWork();

    

private:
    Ui::ArpWorkClass ui;
    QTimer* timer;

private slots://��Ӧ���ܲۺ���
    void send();
    void gethost();
    void getIP();
    void stop();
};
