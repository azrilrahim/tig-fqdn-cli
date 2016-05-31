#-------------------------------------------------
#
# Project created by QtCreator 2016-04-07T12:19:28
#
#-------------------------------------------------

#-----------------------------------#
#                                   #
# Copyright (C) 2016 Azril Rahim    #
# Infoblox Malaysia                 #
# arahim@infoblox.com               #
#                                   #
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
    readme.txt
