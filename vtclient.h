/*
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# Infoblox Malaysia                 #
# arahim@infoblox.com               #
#                                   #
#-----------------------------------#
*/

#ifndef VTCLIENT_H
#define VTCLIENT_H

#include <QObject>
#include <QNetworkAccessManager>
#include <QUrl>
#include <QNetworkReply>
#include <QEventLoop>
#include <QJsonObject>
#include <QJsonDocument>
#include <QJsonArray>
#include <sqlite3.h>
#include <QFile>
#include <QCoreApplication>

struct trustLevel{

    QString childSafety;
    QString privacy;
    QString trustworthy;
    QString reliability;
};

struct webutation {
    QString adultContent;
    quint8 safetyScore;
    QString verdict;
};


struct aptInfo {
    QString md5;
    QString sha256;
    QString genericName;
};

struct domainReport
{
    qint64 domainId;
    QString domainName;
    QString domainInfo;
    QString domainCategory;
    trustLevel WOT;
    webutation reputation;
    QList<aptInfo> aptHosted;
    QList<aptInfo> aptCommunicate;
};

struct hashReport
{
    qint64 hashid; // status also = dbid;
    QString statMsg;
    QString sha256;
    QString md5;
    QString lastUpdateDD;
    QString lastUpdateTT;
    QString description;
    QStringList aliasL;
};

struct findMalwareCommonName
{
    QString name;
    quint32 mhZ;
};

class VtClient : public QObject
{
    Q_OBJECT
public:
    explicit VtClient(QObject *parent = 0);
    ~VtClient();

    int mainEntry(int argc, char *argv[]);
    bool updateDbase();

    bool getReport(bool update = false);
    bool demo (QString FQDN);


private:
    bool HTTPMODE;
    QString inputFile;
    QString outputFile;
    QString streamInput;

    quint64 getNewPrimaryKey();
    QByteArray getData;
    QByteArray postData;

    QString myAPIKEY;

    QString getDomainReportGroupMalwareName(QString domainName);
    bool deleteDomainDB(QString domainName);

    QByteArray pullGETData(QString vtUrl, QString resource, QString param);
    QByteArray pullPOSTData (QString vtUrl, QString resource, QString param);

    QByteArray getJsonObjectData(QJsonObject jo, quint8 parentID = 0);
    QByteArray getJsonArrayData(QJsonArray ja, quint8 parentID = 0);

    hashReport getHASHReport(QString hash);
    hashReport getHASHReportDB3 (QString hash);
    hashReport getHASHReportVT3 (QString hash,qint64 hashid);
    hashReport addHASHReportDB (hashReport hrpt);

    domainReport getDomainReport(QString domainName);

    bool updateNewMalware();

    qint64 getMalwareNameIdDB(QString malwareName);
    quint64 addMalwareNameIdDB(QString malwareName);
    qint64 addMalwareChkSumDB(aptInfo ti);
    qint64 getMalwareChkSumDB(aptInfo ti);

    domainReport getDomainInfoDB(QString domainName, domainReport dr);
    domainReport getDomainInfoVT(QString domainName, domainReport dr);
    domainReport addDomainInfoDB(domainReport dr);

    //bool processFQDNSubmission(QString postData);

    QString getMalwareCommonName(qint64 malwareID);
    QString getMalwareCommonName(QStringList malwareAliases);
    //quint64 getNewPrimaryKey();


    QString dbLoc;
    sqlite3 myDB;





signals:
    void endTransmission();
    void endGETProcess();
    void endPOSTProcess();

private slots:
    //void replyDone(QNetworkReply *rep);
    void getReplyDone(QNetworkReply *rep);
    void postReplyDone(QNetworkReply *rep);

public slots:
};

#endif // VTCLIENT_H
