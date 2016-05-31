/*
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# Infoblox Malaysia                 #
# arahim@infoblox.com               #
#                                   #
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
    vt = new VtClient(0);
    update = false;

    vt->mainEntry(argc,argv);

    delete vt;
    return 0;


}
