/*
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# Infoblox Malaysia                 #
# arahim@infoblox.com               #
#                                   #
#-----------------------------------#
*/

INTRODUCTION
-------------

The TIG application is command line interface (CLI) application
that is designed to produced a set of known malware associated
with a FQDN or an IP address.

TIG is able to accept a single FQDN per query. For multiple queries,
FQDNs inputs must be separated in comma (,). TIG also accept CSV
type format file as input to process multiple queries.


REQUIREMENT
-------------
TIG is a cross platform application that runs on MAC, WIN32/64, UNIX,
OS2 and LINUX. It is a C/C++ application that is coded entirely on
C++ Qt framework. For 64bit compatiblity, all compiliation for TIG
requires the following minimum specifications library to be installed

    *Qt 5.4 (https://www.qt.io/download-open-source/)
    *SQLite 3 (https://www.sqlite.org)
    *GNU C Compiler GCC version 4 (http://www.gnu.org)
    *SSH/SSL version 6 (http://www.openssh.com)


INSTALLATION
-------------

    Compilation
    -----------
    1.  Please ensure all the dependencies libraries specified in the
        requirement sections are properly installed

    2.  Extract all the files in the desired working directory.
        e.g: /home/user/project/TIG

    3.  The create a proper make file for compilation, you need to access
        to the qmake command that comes with Qt framework. qmake command
        must be issued inside the TIG work directory.

        %> cd /home/user/project/TIG
        %> /<qt install dir>/bin/qmake

    4.  After the qmake process is finish, you can called the make command
        to complete the compilation

        %> cd /home/user/project/TIG
        %> make

    5. After a successful compilation, a TIG file will be created.
       To invoke TIG application:

        %> cd /home/user/project/TIG
        %> ./TIG


    SQLITE 3 Database Installation
    ------------------------------
    1.  Copy the tig.db to /opt directory
    2.  Make sure chmod 777 the tig.db file



CONFIGURATION
-------------

    1.  Single FQDN query
        %> ./TIG fqdn?=www.test.com

    2.  multiple FQDN queries (each fqdn is separated by comma ,)
        %> ./TIG fqdn?=www.test.com,www.test2.com,..

    3. Multiple FQDN queries via CSV file
        %> ./TIG if?=csv.file.txt

    4. Force update
        TIG is equipped with auto update when verifying FQDN.
        However its also allow force update. Only 1 single FQDN
        can be forced in a call.
        %> ./TIG fqdn=?www.test.com update


OUTPUT
-------
The output is in CSV format arrange in the following block.
QUERIED_FQDN:TOTAL_MALW_FOUND:TOTAL_MALW_FAMILY_FOUND:MALW_FAMILY1,MALW_FAMILY2,..

e.g
www.aol.com:200:38:sohad,kriptik,zeus...,


MAINTAINER
----------
* Azril Rahim (azril) arahim@infoblox.com


