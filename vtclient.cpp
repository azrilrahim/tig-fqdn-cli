/*
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# Infoblox Malaysia                 #
# arahim@infoblox.com               #
#                                   #
#-----------------------------------#
*/

#include "vtclient.h"
#include <QDebug>
#include <stdio.h>

VtClient::VtClient(QObject *parent) : QObject(parent)
{
    //this->myAPIKEY = "a5af48a69c7dca19a2a5767101177dd1349b51e9b4c1899dc042eb04e594b0e5";
    this->myAPIKEY = "44123e8b4ac6b27f5b45bf440e93c507fa3183dabfbf0682680f4ad9a366e0f6";
    this->dbLoc = "/opt/tig.db";

    this->myDB.openDB(this->dbLoc);
    this->HTTPMODE = false;
}

VtClient::~VtClient()
{
    this->myDB.closeDB();
}

int VtClient::mainEntry(int argc, char *argv[])
{
    bool update;

    this->HTTPMODE = false;
    update = false;

    //no input
    if (argc <=1){
        printf("Please the read me file for list of commands\n");
        return 0;
    }

    this->streamInput.clear();


    //process input argv
    for (int i=1; i< argc;i++)
    {
        QString in = QString::fromLocal8Bit(argv[i]);

        //http mode
        if (in.contains("http?=")){
            this->HTTPMODE = true;
            continue;
        }

        if (in.contains("if?="))
        {
            this->inputFile = in.replace("if?=","").trimmed();
            if(!this->streamInput.isEmpty()){
                printf("Unable to process domains from file if an input stream has been assigned\n");
                return -1;
            }
            continue;
        }

        if (in.contains("-h")){
            printf("Please the read me file for list of commands\n");
            return 0;
        }

        if (in.contains("fqdn?=")){
            this->streamInput = in.replace("fqdn?=","").trimmed();
            if (!this->inputFile.isEmpty())
            {
                printf("Unable to process domains from stream if an input file has been assigned\n");
                return -1;
            }
            continue;
        }

        if (in.contains("update")){
            update = true;
            continue;
        }

        //unknow command
        printf("Unknown command\n");
        return 0;
    }

    //exist if not command issued
    if (this->streamInput.trimmed().isEmpty()){
        printf("Please the read me file for list of commands\n");
        return 0;
    }

    //we need to some formating
    if (this->streamInput.indexOf("'",0) >= 0)
    {
        this->streamInput.remove(0,1);
    }

    if (this->streamInput.indexOf("'",this->streamInput.size()-1) >=0)
    {
        this->streamInput.remove(this->streamInput.size()-1,1);
    }

    this->streamInput.append(","); // to comply with csv format

    if (this->HTTPMODE)
    {
        printf("%s\n",this->streamInput.toStdString().c_str());

        if (this->streamInput.contains("localfile:")){
            this->inputFile = this->streamInput.replace("localfile:","");
            this->streamInput.clear();
        }
        else{
            //decode base64
            QByteArray fb64(this->streamInput.toStdString().c_str());
            this->streamInput = QString::fromLocal8Bit(QByteArray::fromBase64(fb64));
        }
    }

    //open the file
    QFile f;
    if (!this->inputFile.isEmpty()){
        f.setFileName(this->inputFile);

        if (!f.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            printf("Error on opening input file: %s\n",f.errorString().toStdString().c_str());
            return 0;
        }

        this->streamInput.clear();
        this->streamInput = QString::fromLocal8Bit(f.readAll());
        f.close();
    }

    if (this->streamInput.trimmed().isEmpty()){
        printf("Unknown command input\n");
    }


    this->getReport(update);
    return 0;
}


bool VtClient::deleteDomainDB(QString domainName)
{
    //delete all enteries pertain to domain name from the DB;
    domainReport drpt;
    QString deleteQuery;

    //get from database
    drpt = this->getDomainInfoDB(domainName,drpt);
    if (drpt.domainId < 0){
        return false;
    }

    //delete DOMAIN_MALWARE_COMM
    deleteQuery.clear();
    deleteQuery = "Delete from DOMAIN_MALWARE_COMM where DOMAIN_ID = " + QString::number(drpt.domainId) + ";";
    if(!this->myDB.query(deleteQuery)){
        qDebug() << "Error on domain_malware_comm";
        return false;
    }

    //delete DOMAIN_MALWARE_HOSTED
    deleteQuery.clear();
    deleteQuery = "delete from DOMAIN_MALWARE_HOSTED where DOMAIN_ID = " + QString::number(drpt.domainId) + ";";
    if(!this->myDB.query(deleteQuery)){
        qDebug() << "Error on domain_malware_hosted";
        return false;
    }

    //delete domain it self
    deleteQuery.clear();
    deleteQuery = "delete from DOMAIN_INFO where DOMAIN_ID = " + QString::number((drpt.domainId));
    //domainName = domainName.trimmed().toUpper();
    if(!this->myDB.query(deleteQuery)){
        return false;
    }

    return true;
}

/*bool VtClient::demo(QString FQDN)
{
    domainReport drpt;
    QStringList uniqueMalware;



    //get domain report from VT
    drpt = this->getDomainInfoVT(FQDN,drpt);
    if (drpt.domainId < 0){
        printf("Domain not exist\n");
        return false;
    }

    printf("Domain %s information\n",drpt.domainName.toStdString().c_str());
    printf(" Known malware hosted by the domain: %d\n",drpt.aptHosted.size());
    printf(" Known malware communicating with the domain: %d\n\n", drpt.aptCommunicate.size());

    //get hosted malware information;
    uniqueMalware.clear();
    if (drpt.aptHosted.size() > 0){
        printf(" Processing hosted malware\n");
        for(int i = 0; i< drpt.aptHosted.size(); i++){
            hashReport hrpt;
            hrpt = this->getHASHReportVT(drpt.aptHosted.at(i).sha256);

            //process aliases
            uniqueMalware.append(this->getMalwareCommonName(hrpt.aliasL));
        }
        printf(" Removing Duplicate Hosted Malware: %d\n",uniqueMalware.removeDuplicates());
        for (int a=0; a < uniqueMalware.size(); a++){
            printf(" %s",uniqueMalware.at(a).toStdString().c_str());
        }
        printf("\n");
    }
    printf("\n");

    uniqueMalware.clear();
    if (drpt.aptCommunicate.size() > 0){
        printf(" Processing communicating malware\n");
        for(int i = 0; i< drpt.aptCommunicate.size(); i++){
            hashReport hrpt;
            hrpt = this->getHASHReportVT(drpt.aptCommunicate.at(i).sha256);

            //process aliases
            uniqueMalware.append(this->getMalwareCommonName(hrpt.aliasL));
        }
        printf(" Removing Duplicate Hosted Malware: %d\n",uniqueMalware.removeDuplicates());
        for (int a=0; a < uniqueMalware.size(); a++){
            printf(" %s",uniqueMalware.at(a).toStdString().c_str());
        }
        printf("\n");
    }

    printf("\n\n");
    return true;
}*/

QByteArray VtClient::pullGETData(QString vtUrl, QString resource, QString param)
{
    QEventLoop EL;
    QNetworkRequest request;
    QNetworkAccessManager *mgr = new QNetworkAccessManager(this);
    QString getUrl;


    connect(mgr,SIGNAL(finished(QNetworkReply*)),mgr,SLOT(deleteLater()));
    connect(mgr,SIGNAL(finished(QNetworkReply*)),this,SLOT(getReplyDone(QNetworkReply*)));
    connect(this,SIGNAL(endGETProcess()),&EL,SLOT(quit()));

    getUrl = vtUrl;
    getUrl.append("?" + param + "=" + resource +"&");
    getUrl.append("apikey=" + this->myAPIKEY);

    request.setUrl(QUrl(getUrl));
    mgr->get(request);
    EL.exec();

    delete mgr;
    return this->getData;

}

QByteArray VtClient::pullPOSTData(QString vtUrl, QString resource, QString param)
{
    QEventLoop EL;
    QNetworkRequest request;
    QNetworkAccessManager *mgr = new QNetworkAccessManager(this);
    QByteArray postData;

    connect(mgr,SIGNAL(finished(QNetworkReply*)),mgr,SLOT(deleteLater()));
    connect(mgr,SIGNAL(finished(QNetworkReply*)),this,SLOT(postReplyDone(QNetworkReply*)));
    connect(this,SIGNAL(endPOSTProcess()),&EL,SLOT(quit()));

    this->postData.clear();
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    request.setUrl(QUrl(vtUrl));


    postData.clear();
    postData.append(param + "=");
    postData.append(resource);
    postData.append("&");
    postData.append("apikey=");
    postData.append(this->myAPIKEY);

    mgr->post(request,postData);
    EL.exec();

    delete mgr;
    return this->postData;
}

QByteArray VtClient::getJsonObjectData(QJsonObject jo, quint8 parentID)
{
    QString keyName;
    QString tabIndex;
    QByteArray outData;

    outData.clear();

    for (int x=0; x < parentID; x++){
        tabIndex.append("\t");
    }


    for (int i = 0; i < jo.size();i++){

        keyName = jo.keys().at(i);
        if (parentID == 0){
            outData.append("\n");}

        outData.append(tabIndex);
        outData.append(keyName);

        if (jo[keyName].isArray()){
            outData.append("\n");
            outData.append(this->getJsonArrayData(jo[keyName].toArray(),parentID + 1));
            continue;
        }

        if (jo[keyName].isObject()){
            outData.append("\n");
            outData.append(this->getJsonObjectData(jo[keyName].toObject(),parentID + 1));
            continue;
        }

        if (jo[keyName].isDouble()){
            outData.append(" = ");
            outData.append(QString::number(jo[keyName].toDouble()) + "\n");
            continue;
        }
        outData.append(" = ");
        outData.append(jo[keyName].toString());
        outData.append("\n");

    }

    return outData;
}

QByteArray VtClient::getJsonArrayData(QJsonArray ja, quint8 parentID)
{

    QString tabIndex;
    QByteArray outData;

    outData.clear();

    for (int x=0; x < parentID; x++){
        tabIndex.append("\t");
    }

    for (int i =0; i < ja.size(); i++){

        if (ja.at(i).isObject()){
            outData.append(tabIndex);
            if (ja.at(i).toString().isEmpty()){
                outData.append("Data");
            }else
            {
                outData.append(ja.at(i).toString());
            }
            outData.append("\n");
            outData.append(this->getJsonObjectData(ja.at(i).toObject(),parentID+1));
            continue;
        }

        if (ja.at(i).isArray()){
            outData.append(tabIndex);
            outData.append(ja.at(i).toString());
            outData.append("\n");
            outData.append(this->getJsonArrayData(ja.at(i).toArray(),parentID+1));
            continue;
        }


        outData.append(tabIndex);
        outData.append("= " +ja.at(i).toString());
        outData.append("\n");
    }

    return outData;
}


domainReport VtClient::getDomainInfoDB(QString domainName, domainReport dr)
{
    //get domain from DB + related malware

    QList<QSqlRecord> r;
    QString sql;
    domainName = domainName.trimmed().toUpper();
    if(!this->myDB.query("select * from DOMAIN_INFO where DOMAIN_NAME = '" + domainName + "';")){
        qDebug() << "Query Error";
        dr.domainId = -1;
        return dr;
    }

    r = this->myDB.getRecords();

    if (r.size() <= 0){
        dr.domainId = 0;
        //qDebug() << "No records found in DB";
        return dr; //no records
    }

    dr.domainId = r.at(0).value(0).toULongLong();
    dr.domainName = r.at(0).value(1).toString();
    dr.domainInfo = r.at(0).value(2).toString();
    dr.domainCategory = r.at(0).value(3).toString();
    dr.WOT.childSafety = r.at(0).value(4).toString();
    dr.WOT.privacy = r.at(0).value(5).toString();
    dr.WOT.trustworthy = r.at(0).value(6).toString();
    dr.WOT.reliability = r.at(0).value(7).toString();
    dr.reputation.adultContent = r.at(0).value(8).toString();
    dr.reputation.safetyScore = r.at(0).value(9).toInt();
    dr.reputation.verdict = r.at(0).value(10).toString();

    //qDebug() << "Record found! at domain id" << dr.domainId;

    //get the Malware comm;
    sql = "select * from MALWARE_CHKSUM as MN inner join ";
    sql.append("DOMAIN_MALWARE_COMM as DMC on DMC.CHKSUM_ID = MN.CHKSUM_ID ");
    sql.append("where DMC.DOMAIN_ID = " + QString::number(dr.domainId) +";");

    //qDebug() << sql;

    if (this->myDB.query(sql)){

        r = this->myDB.getRecords();
        //qDebug() << "size comm:" << r.size();
        for (int i=0; i < r.size(); i++){
            aptInfo ti;
            ti.sha256 = r.at(i).value(1).toString();
            ti.md5 = r.at(i).value(2).toString();
            dr.aptCommunicate.append(ti);
        }

    }

    //get the Malware hosted;
    sql = "select * from MALWARE_CHKSUM as MN inner join ";
    sql.append("DOMAIN_MALWARE_HOSTED as DMC on DMC.CHKSUM_ID = MN.CHKSUM_ID ");
    sql.append("where DMC.DOMAIN_ID = " + QString::number(dr.domainId) +";");

    if (this->myDB.query(sql)){

        r = this->myDB.getRecords();
        //qDebug() << "size hosted:" << r.size();
        for (int i=0; i < r.size(); i++){
            aptInfo ti;
            ti.sha256 = r.at(i).value(1).toString();
            ti.md5 = r.at(i).value(2).toString();
            dr.aptHosted.append(ti);

        }
    }

    return dr;
}

domainReport VtClient::getDomainInfoVT(QString domainName, domainReport dr)
{
    domainName = domainName.trimmed().toLower();
    //qDebug() << "Obtaining domain from VT";

    QByteArray jsonData = this->pullGETData("https://www.virustotal.com/vtapi/v2/domain/report",domainName,"domain");
    if (jsonData.isEmpty()){
        dr.domainId = -3;
        return dr;
    }

    QJsonDocument jd = QJsonDocument::fromJson(jsonData);
    QJsonObject jo = jd.object();
    QJsonArray ja;
    QJsonObject j;

    dr.domainName = domainName.toUpper();
    dr.domainCategory = jo["Websense ThreatSeeker category"].toString();
    dr.domainInfo = jo["Alexa domain info"].toString();
    dr.reputation.adultContent = jo["Webutation domain info"].toObject()["Adult content"].toString();
    dr.reputation.safetyScore = jo["Webutation domain info"].toObject()["Safety score"].toInt();
    dr.reputation.verdict = jo["Webutation domain info"].toObject()["Verdict"].toString();

    //qDebug() << "DOMAIN CAT" << dr.domainCategory << jo["Websense ThreatSeeker category"];

    //wot
    j = jo["WOT domain info"].toObject();
    dr.WOT.childSafety = j["Child safety"].toString();
    dr.WOT.privacy = j["Privacy"].toString();
    dr.WOT.trustworthy = j["Trustworthiness"].toString();
    dr.WOT.reliability = j["Vendor reliability"].toString();


    //Malware
    ja = jo["detected_referrer_samples"].toArray();
    for (int i=0;i < ja.size(); i++){

        aptInfo ti;
        j = ja.at(i).toObject();
        ti.md5 = j["md5"].toString().trimmed().toUpper();
        ti.sha256 = j["sha256"].toString().trimmed().toUpper();
        dr.aptHosted.append(ti);
    }

    //apt the communicate with domain
    ja = jo["detected_communicating_samples"].toArray();
    for (int i=0;i < ja.size(); i++){
        aptInfo ti;
        j = ja.at(i).toObject();
        ti.md5 = j["md5"].toString().trimmed().toUpper();
        ti.sha256 = j["sha256"].toString().trimmed().toUpper();
        dr.aptCommunicate.append(ti);
    }

    return dr;
}

domainReport VtClient::addDomainInfoDB(domainReport dr)
{
    //add into db
    QString sql;
    //QList<QSqlRecord> r;
    qint64 pk;
    qint64 chksumID;

    //get unique primaryKey for new data
    pk = this->getNewPrimaryKey();

    sql = "insert into DOMAIN_INFO (DOMAIN_ID,DOMAIN_NAME,DOMAIN_INFO,DOMAIN_CATEGORY,WOT_CHILD_SAFETY,WOT_PRIVACY,";
    sql.append("WOT_THRUSTWORTY,WOT_RELIABILITY,REP_ADULT_CONTENT,REP_SAFETY_SCORE,REP_VERDICT) values ");
    sql.append("(");
    sql.append(QString::number(pk) + ",");
    sql.append("'" + dr.domainName + "',");
    sql.append("'" + dr.domainInfo + "',");
    sql.append("'" + dr.domainCategory + "',");
    sql.append("'" + dr.WOT.childSafety + "',");
    sql.append("'" + dr.WOT.privacy + "',");
    sql.append("'" + dr.WOT.trustworthy + "',");
    sql.append("'" + dr.WOT.reliability + "',");
    sql.append("'" + dr.reputation.adultContent + "',");
    sql.append(QString::number(dr.reputation.safetyScore) + ",");
    sql.append("'" + dr.reputation.verdict + "');");

    //qDebug() << "new data sql:" << sql;

    if (!this->myDB.query(sql)){
        qDebug() << "query fail";
        dr.domainId = -4;
        return dr;
    }

    //qDebug() << "insert success. get id";
    dr.domainId = pk;

    //add malware hosted into checksum
    for (int i = 0; i < dr.aptHosted.size(); i++){
        aptInfo ti = dr.aptHosted.at(i);
        chksumID = this->addMalwareChkSumDB(ti);

        if (chksumID > 0){
            //add malware into DOMAIN_MALWARE_HOSTED
            sql = "insert into DOMAIN_MALWARE_HOSTED (DOMAIN_ID,CHKSUM_ID) values (";
            sql.append(QString::number(dr.domainId) + "," + QString::number(chksumID) + ");");
            if(this->myDB.query(sql)){
                //qDebug() << "domain_malware_hosted add";
            }
        }
    }

    //add malware hosted into checksum
    for (int i = 0; i < dr.aptCommunicate.size(); i++){
        aptInfo ti = dr.aptCommunicate.at(i);
        //qDebug() << "Checking for" << ti.sha256;
        chksumID = this->addMalwareChkSumDB(ti);

        if (chksumID > 0){
            //add malware into DOMAIN_MALWARE_COMM
            sql = "insert into DOMAIN_MALWARE_COMM (DOMAIN_ID,CHKSUM_ID) values (";
            sql.append(QString::number(dr.domainId) + "," + QString::number(chksumID) + ");");
            if(this->myDB.query(sql)){
                //qDebug() << "domain_malware_comm add";
            }
        }
    }

    return dr;
}



qint64 VtClient::getMalwareChkSumDB(aptInfo ti)
{
    //return checksum id;
    QString sql;
    QList<QSqlRecord>r;

    sql = "select CHKSUM_ID from MALWARE_CHKSUM where SHA256 ='" + ti.sha256 + "';";

    if (!this->myDB.query(sql)){
        qDebug() << "error on getmalwarechksum based on ti: " + sql;
        return -1;
    }

    r = this->myDB.getRecords();

    if (r.size() <= 0){
        //qDebug() << "No malware check sum record";
        return 0;
    }

    return r.at(0).value(0).toULongLong();
}


qint64 VtClient::addMalwareChkSumDB(aptInfo ti)
{
    QString sql;
    qint64 id = 0;

    id = this->getMalwareChkSumDB(ti);

    if (id < 0){
        return id; //something wrong
    }

    if (id > 0){
        return id; //malware exist.. dont add
    }

    //no malware exist! add new malware checksum;
    id = this->getNewPrimaryKey();

    //add malware in check sum
    sql = "insert into MALWARE_CHKSUM (CHKSUM_ID, SHA256,MD5) values (";
    sql.append(QString::number(id) + ",");
    sql.append("'" + ti.sha256 + "',");
    sql.append("'" + ti.md5 + "');");

    if (!this->myDB.query(sql)){
        qDebug() << "error on add malware checksum " + sql;
        return -1;
    }

    return id;
}

domainReport VtClient::getDomainReport(QString domainName)
{
    domainReport drpt;

    //get from database
    drpt = this->getDomainInfoDB(domainName,drpt);
    if (drpt.domainId < 0){
        return drpt;
    }

    if (drpt.domainId == 0){
        //no data, need to fetch from VT
        drpt = this->getDomainInfoVT(domainName,drpt);
        if (drpt.domainId < 0 ){
            //vt error
            return drpt;
        }

        //we need to add everything from VT to DB
        drpt = this->addDomainInfoDB(drpt);
        if (drpt.domainId <= 0){
            return drpt;
        }
    }

    return drpt;
}

bool VtClient::getReport(bool update)
{
    QString output;
    QStringList domains;
    QString tmp;
    output.clear();

        domains = this->streamInput.split(",");
        //output.append("num of domains: " + QString::number(domains.size()) + "::" + this->streamInput);
        for(int i=0; i < domains.size();i++){
            QCoreApplication::processEvents();

            tmp = domains.at(i);
            tmp = tmp.replace("\r","");
            tmp = tmp.replace("\n","");
            //output.append(tmp + "++");
            if (!tmp.isEmpty()){

                if (update){
                    qDebug() << "Updating domain" << tmp << this->deleteDomainDB(tmp);
                }
                qDebug() << "processing:" << tmp;
                output.append(this->getDomainReportGroupMalwareName(tmp));
            }
        }


    //produced html output if required
    if (this->HTTPMODE){

        QString html;
        QString content;

        //format output
        output = output.replace("\n","<br>\n");
        content.append("<html><font face='monospace'>" + output + "</html>");
        html.clear();
        html.append("Content-type:text/html\r\nContent-Length:" + QString::number(content.size()) + "\r\n\r\n");
        html.append(content);

        //reassigned
        output.clear();
        output = html;
        content.clear();
    }


    //print output
    printf("%s",output.toStdString().c_str());
    return true;
}


QString VtClient::getDomainReportGroupMalwareName(QString domainName)
{
    //this cli version is specifically to find domain and its associated malware;
    domainReport rpt;
    hashReport hrpt;
    QStringList uniqueMalware;

    QString rs;
    rs.clear();

    /*
     * 1. Get domain from DB
     * 2. If DB == 0
     * 3.   Fetch new from VT
     * 4.   Save VT into DB
     * 5.   get domain from DB
     *
     */

    //all update or add new are regardless of the domain or hash report

    rpt = this->getDomainReport(domainName);
    if (rpt.domainId <= 0){
        return rs;
    }

    uniqueMalware.clear();

    //qDebug() << "fetching apt hosted:" << rpt.aptHosted.size();
    for (int i=0;i < rpt.aptHosted.size();i++){
        hrpt = this->getHASHReport(rpt.aptHosted.at(i).sha256);

        if (!hrpt.description.trimmed().isEmpty()){
            uniqueMalware.append(hrpt.description);
        }
    }

    //qDebug() << "fetching apt communicate:" << rpt.aptCommunicate.size();
    for (int i=0;i < rpt.aptCommunicate.size();i++){
        hrpt = this->getHASHReport(rpt.aptCommunicate.at(i).sha256);

        if (!hrpt.description.trimmed().isEmpty()){
            uniqueMalware.append(hrpt.description);
        }
    }

    //filter unique malware;
    uniqueMalware.removeDuplicates();

    //append domain names
    rs.append(rpt.domainName.trimmed() + ":");

    //append total malware found
    rs.append(QString::number(rpt.aptHosted.size() + rpt.aptCommunicate.size()) + ":");

    //append number of group unique malware;
    rs.append(QString::number(uniqueMalware.size()) + ":");

    //append unique group malware found
    for (int i=0; i < uniqueMalware.size(); i++){
        rs.append(uniqueMalware.at(i).trimmed() + ";");
    }

    //just format
    if (uniqueMalware.size() ==0){
        rs.append("Not Available");
    }

    //append end of line
    rs.append(",\n");

    //return result;
    return rs;
}



/*QByteArray VtClient::getPostData(QString url)
{
    QEventLoop EL;
    QNetworkRequest request;
    QNetworkAccessManager *mgr = new QNetworkAccessManager(this);
    QByteArray postData;

    connect(mgr,SIGNAL(finished(QNetworkReply*)),mgr,SLOT(deleteLater()));
    connect(mgr,SIGNAL(finished(QNetworkReply*)),this,SLOT(replyDone(QNetworkReply*)));
    connect(this,SIGNAL(endTransmission()),&EL,SLOT(quit()));

    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/x-www-form-urlencoded");
    request.setUrl(QUrl("https://www.virustotal.com/vtapi/v2/url/scan"));

    postData.clear();
    postData.append("url=");
    postData.append(url);
    postData.append("&");
    postData.append("apikey=a5af48a69c7dca19a2a5767101177dd1349b51e9b4c1899dc042eb04e594b0e5");

    mgr->post(request,postData);
    EL.exec();

    qDebug() << this->replyData;

    return this->replyData;
}*/

/*void VtClient::replyDone(QNetworkReply *rep)
{
    this->replyData.clear();
    this->replyData = rep->readAll();
    emit this->endTransmission();
}*/



hashReport VtClient::getHASHReport(QString hash){

    hashReport hrpt;
    hrpt.hashid = 0;


    hrpt = this->getHASHReportDB3(hash);
    if((hrpt.hashid > 0) && (hrpt.aliasL.size() > 0)){
        hrpt.description = this->getMalwareCommonName(hrpt.aliasL);
        return hrpt;
    }

    //get new hash report online
    hrpt = this->getHASHReportVT3(hash,hrpt.hashid);
    if (hrpt.hashid > 0){
        hrpt = this->addHASHReportDB(hrpt);
        hrpt.description = this->getMalwareCommonName(hrpt.aliasL);
        return hrpt;
    }
    return hrpt;
}


hashReport VtClient::getHASHReportDB3(QString hash)
{
    QList<QSqlRecord> r;
    QString sql;
    hashReport rpt;

    hash = hash.toUpper().trimmed();

    rpt.hashid = 0;
    rpt.md5.clear();
    rpt.sha256.clear();
    rpt.lastUpdateDD.clear();
    rpt.lastUpdateTT.clear();
    rpt.aliasL.clear();
    rpt.description.clear();


    //check hash size
    if ((hash.size() < 32) || (hash.size() > 64)){

        rpt.hashid = 0;
        rpt.statMsg = "Error: Invalid hash info";
        return rpt;
    }

    if (!this->myDB.isOpen()){
        rpt.statMsg = "DB is closed";
        rpt.hashid = 0;
        return rpt;
    }


    sql = "select * from MALWARE_CHKSUM where ";
    if (hash.size() == 32){
        sql.append("MD5 = '" + hash +"';");
    }

    if (hash.size() == 64){
        sql.append("SHA256 = '" + hash + "';");
    }

    if (!this->myDB.query(sql)){
        qDebug() << "Error: " + sql;
        rpt.hashid = 0;
        rpt.statMsg = "db error";
        return rpt;
    }

    r = this->myDB.getRecords();

    //if no records
    if (r.size() <= 0)
    {
        //no such hash
        rpt.hashid = 0;
        rpt.statMsg = "No such Hash";
    }

    //get rpt;
    rpt.hashid = r.at(0).value("CHKSUM_ID").toULongLong(); // status is checksum id
    rpt.statMsg = "record found";
    rpt.md5 = r.at(0).value("MD5").toString();
    rpt.sha256 = r.at(0).value("SHA256").toString();
    rpt.lastUpdateDD = r.at(0).value("SCAN_DATE").toString();
    rpt.lastUpdateTT = r.at(0).value("SCAN_TIME").toString();

    //we need to get the alias so we can figure out the actual malware name;
    rpt.description = "";

    //get Alias;
    //qDebug() << "Finding alias for hash" << rpt.hashid;

    //inner join sql
    sql = "select NAME from MALWARE_NAME as MN inner join MALWARE_ALIAS as MA ";
    sql.append("on MN.NAME_ID = MA.NAME_ID where MA.CHKSUM_ID = "+ QString::number(rpt.hashid) + ";");

    if (!this->myDB.query(sql)){
        qDebug() << "DB Error" + sql;
        rpt.hashid = 0;
        rpt.statMsg = "DB Error";
        return rpt;
    }

    r = this->myDB.getRecords();
    if (r.size() <= 0){
        //qDebug() << "No records on alias found for:" << rpt.hashid;
        return rpt;
    }

    //qDebug() << "hash malware alias found are" << r.size();

    if (r.size() > 0){
        //qDebug() << "importing alias";
        for(int i=0; i < r.size(); i++){
             rpt.aliasL.append(r.at(i).value(0).toString());
        }
    }

    //if we have malware alias, we can find common name
    return rpt;
}


hashReport VtClient::getHASHReportVT3(QString hash, qint64 hashid)
{
    //QString sql;
    QStringList dl;
    QString tmp;

    QJsonObject jo;
    QJsonDocument jd;

    //quint64 chksum_id;
    //quint64 name_id;

    hashReport rpt;

    //clear all values
    rpt.hashid = hashid; //we reassigned
    rpt.md5.clear();
    rpt.sha256.clear();
    rpt.lastUpdateDD.clear();
    rpt.lastUpdateTT.clear();
    rpt.aliasL.clear();
    rpt.description.clear();


    hash = hash.toLower();
    //chksum_id = cid;

    //pull data from VT
    //qDebug() << "Obtaining data from VT";
    QByteArray jsonData = this->pullPOSTData("http://www.virustotal.com/vtapi/v2/file/report",hash,"resource");
    if (jsonData.isEmpty()){
        qDebug() << "getHASHReportVT3::No data from POST";
        return rpt;
    }

    jd = QJsonDocument::fromJson(jsonData);
    jo = jd.object();

    //get the particulars
    rpt.md5 = jo["md5"].toString().toUpper();
    rpt.sha256 = jo["sha256"].toString().toUpper();
    dl = jo["scan_date"].toString().split(" ");
    if (dl.size() >= 2){
        rpt.lastUpdateDD = dl.at(0);
        rpt.lastUpdateTT = dl.at(1);
    }else
    {
        rpt.lastUpdateDD = "";
        rpt.lastUpdateTT = "";
    }


    //get aliases
    QJsonObject scans = jo["scans"].toObject();
    QJsonObject name;

    for (int i =0; i < scans.size(); i++){
        QString vendor = scans.keys().at(i);
        name = scans[vendor].toObject();
        tmp = name["result"].toString().trimmed();
        if (tmp.size() > 0){
            rpt.aliasL.append(tmp.toUpper());
        }
    }
    //qDebug() << "alias obtain from VT:" << rpt.aliasL.size();

    //if success rpt.hashid is 1;
    return rpt;


}

hashReport VtClient::addHASHReportDB(hashReport hrpt)
{
    //add or update hash report
    QString sql;
    qint64 name_id;

    sql.clear();


    //ADD MALWARE IN OR UPDATE MALWAR_CHKSUM
    if (hrpt.hashid > 0){
        //update
        //qDebug() << "updating MALWARE_CHKSUM";
        sql = "update MALWARE_CHKSUM set ";
        sql.append("SHA256='" + hrpt.sha256 + "',");
        sql.append("MD5='" + hrpt.md5 + "',");
        sql.append("SCAN_DATE='" + hrpt.lastUpdateDD + "',");
        sql.append("SCAN_TIME='" + hrpt.lastUpdateTT + "' ");
        sql.append("where CHKSUM_ID = " + QString::number(hrpt.hashid) + ";");
    }
    else
    {
        //qDebug() << "Adding MALWARE_CHKSUM";
        hrpt.hashid = this->getNewPrimaryKey();
        sql = "insert into CHKSUM_ID, MALWARE_CHKSUM (SHA256,MD5,SCAN_DATE,SCAN_TIME) values (";
        sql.append(QString::number(hrpt.hashid) + ",");
        sql.append("'" + hrpt.sha256 + "',");
        sql.append("'" + hrpt.md5 + "',");
        sql.append("'" + hrpt.lastUpdateDD + "',");
        sql.append("'" + hrpt.lastUpdateTT + "');");
    }

    //update database on malware checksum;
    if (!this->myDB.query(sql)){
        qDebug() << "fail on " << sql;
        hrpt.hashid = 0;
        return hrpt;
    }

    //FIND MALWARE NAME ID in MALWARE_NAME, ELSE ADD ONE
    for (int i=0; i < hrpt.aliasL.size(); i++){

        name_id = this->getMalwareNameIdDB(hrpt.aliasL.at(i));

        //no records found
        if (name_id == 0){
            //qDebug() << "Adding New Malware";
            name_id = this->addMalwareNameIdDB(hrpt.aliasL.at(i));
            continue;
        }

        if (name_id > 0){
            //Add entry into MALWARE_ALIAS
            sql = "insert into MALWARE_ALIAS (CHKSUM_ID, NAME_ID) values (";
            sql.append(QString::number(hrpt.hashid) + "," + QString::number(name_id) + ");");
            this->myDB.query(sql);
            continue;
        }
    }

    return hrpt;

}



qint64 VtClient::getMalwareNameIdDB(QString malwareName)
{

    QList<QSqlRecord> r;

    if (!this->myDB.query("select name_id from MALWARE_NAME where name = '" + malwareName + "';")){
        return -1;
    }
    r = this->myDB.getRecords();

    if (r.size() <= 0){
        return 0; //no records found
    }

    return r.at(0).value(0).toULongLong();
}

quint64 VtClient::addMalwareNameIdDB(QString malwareName)
{
    quint64 id;
    QString sql;

    malwareName = malwareName.toUpper();
    id = this->getNewPrimaryKey();

    sql = "insert into MALWARE_NAME (NAME_ID,NAME) values (";
    sql.append(QString::number(id) + ",'" + malwareName + "');");

    //add
    if (!this->myDB.query(sql)){
        return 0;
    }

    //return primary key
    return id;
}

void VtClient::getReplyDone(QNetworkReply *rep)
{
    this->getData = rep->readAll();
    emit this->endGETProcess();
}


void VtClient::postReplyDone(QNetworkReply *rep)
{
    this->postData = rep->readAll();
    emit this->endPOSTProcess();
}

QString VtClient::getMalwareCommonName(QStringList malwareAliases)
{
    QString aliasesCombined;
    QString commonName;
    QList<findMalwareCommonName> names;
    QList<findMalwareCommonName> sortedNames;
    QRegExp re("\\d*");
    bool namesUpdate;

    commonName.clear();

    if (malwareAliases.size() <= 0){
        return commonName;
    }

    for (int i=0; i < malwareAliases.size(); i++){
        //qDebug() << malwareAliases.at(i);
        aliasesCombined.append(malwareAliases.at(i).toLower() + " ");
    }

    //remove common annotation
    aliasesCombined = aliasesCombined.replace("."," ");
    aliasesCombined = aliasesCombined.replace("/"," ");
    aliasesCombined = aliasesCombined.replace(":"," ");
    aliasesCombined = aliasesCombined.replace("("," ");
    aliasesCombined = aliasesCombined.replace(")"," ");
    aliasesCombined = aliasesCombined.replace("["," ");
    aliasesCombined = aliasesCombined.replace("]"," ");

    //remove general words
    aliasesCombined = aliasesCombined.replace("engine"," ");
    aliasesCombined = aliasesCombined.replace("variant"," ");
    aliasesCombined = aliasesCombined.replace("lookslike"," ");
    aliasesCombined = aliasesCombined.replace("suspicious", " ");
    aliasesCombined = aliasesCombined.replace("packed"," ");
    aliasesCombined = aliasesCombined.replace("pack"," ");
    aliasesCombined = aliasesCombined.replace("fakealert"," ");
    aliasesCombined = aliasesCombined.replace("malicious"," ");
    aliasesCombined = aliasesCombined.replace("virtool"," ");
    aliasesCombined = aliasesCombined.replace("html"," ");
    aliasesCombined = aliasesCombined.replace("redir"," ");

    //remove common malware type
    aliasesCombined = aliasesCombined.replace("malware"," ");
    aliasesCombined = aliasesCombined.replace("generic"," ");
    aliasesCombined = aliasesCombined.replace("i-worm", " ");
    aliasesCombined = aliasesCombined.replace("worm"," ");
    aliasesCombined = aliasesCombined.replace("backdoor"," ");
    aliasesCombined = aliasesCombined.replace("trojan"," ");
    aliasesCombined = aliasesCombined.replace("trojware"," ");
    aliasesCombined = aliasesCombined.replace("bot"," ");
    aliasesCombined = aliasesCombined.replace("zbot"," ");
    aliasesCombined = aliasesCombined.replace("clicker"," ");


    //remove common programming script language
    aliasesCombined = aliasesCombined.replace("js"," ");
    aliasesCombined = aliasesCombined.replace("vb"," ");
    aliasesCombined = aliasesCombined.replace("heur"," ");
    aliasesCombined = aliasesCombined.replace("gen"," ");
    aliasesCombined = aliasesCombined.replace("autoit"," ");
    aliasesCombined = aliasesCombined.replace("autorun"," ");
    aliasesCombined = aliasesCombined.replace("script-inf"," ");

    //remove common platform name
    aliasesCombined = aliasesCombined.replace("win32"," ");
    aliasesCombined = aliasesCombined.replace("w32"," ");

    QStringList aliasSplit = aliasesCombined.split(" ");
    QString tgt;


    for (int b=0; b < aliasSplit.size(); b++){
        tgt = aliasSplit.at(b).trimmed();
        if ((!tgt.isEmpty()) && (tgt.size() > 3) && (tgt.isSimpleText()) && (!re.exactMatch(tgt))){

            //check if the aliassplit already in the names list
            namesUpdate = false;
            for (int c = 0; c < names.size(); c++){

                if (names.at(c).name.compare(aliasSplit[b]) == 0){
                    //add the name
                    findMalwareCommonName name;
                    name = names.at(c);
                    name.mhZ++; //increase the frequencies

                    //update the list
                    names.replace(c,name);
                    namesUpdate = true;
                    break;
                }
            }

            if (!namesUpdate){

                //add the name into the list
                findMalwareCommonName name;
                name.name = aliasSplit[b];
                name.mhZ = 1;
                names.append(name);
            }
        }
    }

    //sort the highest frequencies
    findMalwareCommonName highest;
    int highestLoc;

    if (names.size() <=0){
        return ""; //common name is none;
    }

    while(1){

        //find the highest score and loc
        highest = names.at(0);
        highestLoc = 0;
        for (int i=1;i < names.size(); i++){
            if (names.at(i).mhZ > highest.mhZ){
                highest = names.at(i);
                highestLoc = i;
            }
        }

        //add the ranks into sortnames
        sortedNames.append(highest);
        names.removeAt(highestLoc);

        if (names.size() == 0){
            break; //exit while loop
        }
    }

    //the top most is the malware name
    commonName =  sortedNames.at(0).name;
    return commonName;
}

QString VtClient::getMalwareCommonName(qint64 malwareID)
{
    //read malware id from database;

    QList<QSqlRecord> r;
    QList<findMalwareCommonName> names;
    QList<findMalwareCommonName> sortedNames;
    QRegExp re("\\d*");
    bool namesUpdate;

    QString aliasesCombined;

    QString commonName;
    QString sql;

    sql = "select NAME from MALWARE_NAME as MN inner join MALWARE_ALIAS as MA ";
    sql.append("on MN.NAME_ID = MA.NAME_ID where MA.CHKSUM_ID = " + QString::number(malwareID) + ";");

    //query db and get records
    this->myDB.query(sql);
    r = this->myDB.getRecords();

    qDebug() << "record size:" << r.size();



    for (int i=0; i < r.size(); i++){
        aliasesCombined.append(r.at(i).value(0).toString().toLower() + " ");
    }


    //remove common annotation
    aliasesCombined = aliasesCombined.replace("."," ");
    aliasesCombined = aliasesCombined.replace("/"," ");
    aliasesCombined = aliasesCombined.replace(":"," ");
    aliasesCombined = aliasesCombined.replace("("," ");
    aliasesCombined = aliasesCombined.replace(")"," ");
    aliasesCombined = aliasesCombined.replace("["," ");
    aliasesCombined = aliasesCombined.replace("]"," ");


    //remove general words
    aliasesCombined = aliasesCombined.replace("engine"," ");
    aliasesCombined = aliasesCombined.replace("variant"," ");
    aliasesCombined = aliasesCombined.replace("lookslike"," ");
    aliasesCombined = aliasesCombined.replace("suspicious", " ");
    aliasesCombined = aliasesCombined.replace("packed"," ");
    aliasesCombined = aliasesCombined.replace("pack"," ");
    aliasesCombined = aliasesCombined.replace("fakealert"," ");
    aliasesCombined = aliasesCombined.replace("malicious"," ");
    aliasesCombined = aliasesCombined.replace("virtool"," ");


        //QString alias = r.at(i).value(0).toString().toLower();
        //alias = alias.replace("."," ");
        //alias = alias.replace("/", " ");




    //remove common malware type
    aliasesCombined = aliasesCombined.replace("malware"," ");
    aliasesCombined = aliasesCombined.replace("generic"," ");
    aliasesCombined = aliasesCombined.replace("i-worm", " ");
    aliasesCombined = aliasesCombined.replace("worm"," ");
    aliasesCombined = aliasesCombined.replace("backdoor"," ");
    aliasesCombined = aliasesCombined.replace("trojan"," ");
    aliasesCombined = aliasesCombined.replace("trojware"," ");
    aliasesCombined = aliasesCombined.replace("bot"," ");
    aliasesCombined = aliasesCombined.replace("zbot"," ");

    //remove common programming script language
    aliasesCombined = aliasesCombined.replace("js"," ");
    aliasesCombined = aliasesCombined.replace("vb"," ");
    aliasesCombined = aliasesCombined.replace("heur"," ");
    aliasesCombined = aliasesCombined.replace("gen"," ");

    //remove common platform name
    aliasesCombined = aliasesCombined.replace("win32"," ");
    aliasesCombined = aliasesCombined.replace("w32"," ");


    QStringList aliasSplit = aliasesCombined.split(" ");
    QString tgt;

    for (int b=0; b < aliasSplit.size(); b++){
        tgt = aliasSplit.at(b).trimmed();
        if ((!tgt.isEmpty()) && (tgt.size() > 3) && (tgt.isSimpleText()) && (!re.exactMatch(tgt))){

            //check if the aliassplit already in the names list
            namesUpdate = false;
            for (int c = 0; c < names.size(); c++){

                if (names.at(c).name.compare(aliasSplit[b]) == 0){
                    //add the name
                    findMalwareCommonName name;
                    name = names.at(c);
                    name.mhZ++; //increase the frequencies

                    //update the list
                    names.replace(c,name);
                    namesUpdate = true;
                    break;
                }
            }

            if (!namesUpdate){

                //add the name into the list
                findMalwareCommonName name;
                name.name = aliasSplit[b];
                name.mhZ = 1;
                names.append(name);
            }
        }
    }

    qDebug() << "names final size:" << names.size();

    //sort the highest frequencies
    findMalwareCommonName highest;
    int highestLoc;
    while(1){

        //find the highest score and loc
        highest = names.at(0);
        highestLoc = 0;
        for (int i=1;i < names.size(); i++){
            if (names.at(i).mhZ > highest.mhZ){
                highest = names.at(i);
                highestLoc = i;
            }
        }

        //add the ranks into sortnames
        sortedNames.append(highest);
        names.removeAt(highestLoc);

        if (names.size() == 0){
            break; //exit while loop
        }
    }

    for (int i = 0; i < sortedNames.size(); i++){
        qDebug() << sortedNames.at(i).name << sortedNames.at(i).mhZ;
    }

    //the top most is the malware name
    qDebug() << "malware name is" << sortedNames.at(0).name;
    return commonName;
}


quint64 VtClient::getNewPrimaryKey()
{
    //get new primary is pseudo generate algo for creating DB primary
    //key based DDMMYYHHMMSS. This is to replace DB default auto increment
    //that will lead inconsistantcy during data update, append, migration
    //and rollback
    QDateTime now;
    QString utc;
    quint64 primaryKey = 0;

    utc = now.currentDateTimeUtc().toString();
    utc.remove(QRegExp("[^0-9]"));
    primaryKey = utc.toLongLong() + now.currentMSecsSinceEpoch();

    return primaryKey;
}




