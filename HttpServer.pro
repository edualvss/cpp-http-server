TEMPLATE = app
CONFIG += console c++17
CONFIG -= app_bundle
CONFIG -= qt

INCLUDEPATH = /opt/homebrew/Cellar/boost/1.86.0_2/include

LIBS += -L/opt/homebrew/Cellar/boost/1.86.0_2/lib -lboost_system

SOURCES += \
        main.cpp
