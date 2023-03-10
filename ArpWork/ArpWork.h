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

//MAC地址
struct mac_address {
    u_char byte[6];
};

struct eth_head {
    mac_address destMAC;    	//目的MAC地址 6字节  
    mac_address sourceMAC;      //源MAC地址 6字节  
    u_short     type;           //帧类型, 0x0806是ARP帧的类型值
};
#pragma pack(1)
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

class ArpWork : public QMainWindow
{
    Q_OBJECT

public:
    ArpWork(QWidget *parent = nullptr);
    ~ArpWork();

    

private:
    Ui::ArpWorkClass ui;
    QTimer* timer;

private slots://相应功能槽函数
    void send();
    void gethost();
    void getIP();
    void stop();
};
