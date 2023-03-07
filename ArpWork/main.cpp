#include "ArpWork.h"
#include <QtWidgets/QApplication>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    ArpWork w;
    w.show();
    return a.exec();
}
