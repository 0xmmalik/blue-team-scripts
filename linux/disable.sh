#!/usr/bin/env bash


echo "STOPPING $1..."
systemctl stop $1
echo "DISABLING $1..."
systemctl disable $1
if [ ! -z $2 ]
then
    if [ $2 = "-u" ]
    then
        echo "UNINSTALLING $1..."
        apt remove $1
    else 
        echo "Unknown option " $2
    fi
else
    echo "$1 is still installed..."
fi
