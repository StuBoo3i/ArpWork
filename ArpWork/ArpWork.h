#pragma once

#include <QtWidgets/QMainWindow>
#include "ui_ArpWork.h"

class ArpWork : public QMainWindow
{
    Q_OBJECT

public:
    ArpWork(QWidget *parent = nullptr);
    ~ArpWork();

private:
    Ui::ArpWorkClass ui;

private slots://��Ӧ���ܲۺ���
    void send();
    void gethost();
    void getIP();
private :

};
