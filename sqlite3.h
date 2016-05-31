/*
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# Infoblox Malaysia                 #
# arahim@infoblox.com               #
#                                   #
#-----------------------------------#
*/

#ifndef SQLITE3_H
#define SQLITE3_H

#include <QObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QDebug>
#include <QSqlQuery>
#include <QSqlRecord>
#include <QList>

class sqlite3 : public QObject
{
    Q_OBJECT
public:
    explicit sqlite3(QObject *parent = 0);
    bool openDB(QString db);
    bool query(QString sql);
    bool closeDB();
    bool isOpen();
    QString getLastError();

    QList<QSqlRecord> getRecords();
    ~sqlite3();

private:

    bool openSQL3(QString db);
    QSqlQuery Q;
    QSqlDatabase *DB;
    QList<QSqlRecord> records;

signals:

public slots:
};

#endif // SQLITE3_H
