
#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# azrilazam@gmail.com               #
#                                   #
# This code is under GNU Open Source#
# license. You are free to modified #
# it as long the where credits due  #
#-----------------------------------#

QT       += core network sql

QT       -= gui

TARGET = TIG
CONFIG   += console
CONFIG   -= app_bundle

TEMPLATE = app


SOURCES += main.cpp \
    sqlite3.cpp \
    vtclient.cpp

HEADERS += \
    sqlite3.h \
    vtclient.h

DISTFILES += \
    readme.txt \
    changelog.txt \
    tig.db
