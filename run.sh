#!/bin/bash

echo "running py-vereinsflieger as daemon" | tee -a logfile.txt

screen -dmS py-vereinsflieger ./daemon.sh
screen -dmS py-vereinsflieger-reporter ./reporter_daemon.sh

echo "in order to view the output run 'screen -r py-vereinsflieger'" | tee -a logfile.txt

