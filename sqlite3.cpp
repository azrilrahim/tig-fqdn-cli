/*
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# Infoblox Malaysia                 #
# arahim@infoblox.com               #
#                                   #
#-----------------------------------#
*/

#include "sqlite3.h"

sqlite3::sqlite3(QObject *parent) : QObject(parent)
{
    //this->DB->close();
    this->records.clear();
}

sqlite3::~sqlite3()
{

}

bool sqlite3::openDB(QString db)
{
    return this->openSQL3(db);
}

bool sqlite3::closeDB()
{
    if (this->DB->isOpen()){
        this->DB->close();
        delete this->DB;
        QSqlDatabase::removeDatabase("mysqlite3");
    }

    return true;
}

QList<QSqlRecord> sqlite3::getRecords()
{
    return this->records;
}
bool sqlite3::isOpen()
{
    return this->DB->isOpen();
}

bool sqlite3::query(QString sql)
{
    this->records.clear();

    if (!this->DB->isOpen()){
        return false;
    }


    if (!this->Q.exec(sql)){
        return false;
    }

    //get all the records;
    while (this->Q.next()) {
        this->records.append(this->Q.record());
    }
    return true;
}

bool sqlite3::openSQL3(QString db)
{
    this->DB = new QSqlDatabase(QSqlDatabase::addDatabase("QSQLITE","mysqlite3"));
    this->DB->setDatabaseName(db);

    if (!this->DB->open()){
        qDebug() << "DB error open:" << this->DB->lastError().text();
        delete this->DB;
        QSqlDatabase::removeDatabase("mysqlite3");
        return false;
    }
    this->Q = QSqlQuery(*this->DB);
    return true;
}

QString sqlite3::getLastError()
{
    return this->DB->lastError().text();
}
