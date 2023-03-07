#include "ArpWork.h"

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

}
