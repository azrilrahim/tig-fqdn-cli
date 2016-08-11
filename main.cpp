/*
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# azrilazam@gmail.com               #
#                                   #
# This code is under GNU Open Source#
# license. You are free to modified #
# it as long the where credits due  #
#-----------------------------------#
*/

#include <QCoreApplication>
#include <vtclient.h>
#include <QLoggingCategory>

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    VtClient *vt;
    bool update;
    update = false;

    QLoggingCategory::setFilterRules("qt.network.ssl.w arning=false");

    /* testing */

    QRegExp exp;

    exp.setPattern("\\d{1,3}.\\d{1,3}.\\d{1,3}.\\d{1,3}");
    qDebug() << exp.exactMatch("192.133.144.155");
    qDebug() << exp.exactMatch("1.0.0.1");
    qDebug() << exp.exactMatch("1.1.a");

    exp.setPattern("[a-zA-Z0-9_-]{1,63}.[a-zA-Z0-9_-]{1,63}.[a-zA-Z]{1,4}");
    //qDebug() << "hantu" << exp.exactMatch("hantu");

    //exp.setPattern("\\w");
    qDebug() << "mimos" << exp.exactMatch("www.mi!mos23.com");
    qDebug() << "123" << exp.exactMatch("www.123.com");
    qDebug() << "xyz" << exp.exactMatch("www.xyz-123_1.com");

    exp.setPattern("\\w{5}");
    qDebug() << "makan" << exp.exactMatch("makan");
    qDebug() << "nasi" << exp.exactMatch("nasi");
    return 0;

    vt = new VtClient(0);
    update = false;

    vt->mainEntry(argc,argv);

    delete vt;
    return 0;


}
