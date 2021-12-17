#!/bin/bash

echo "running py-vereinsflieger as daemon" | tee -a logfile.txt

screen -dmS py-vereinsflieger ./daemon.sh

echo "in order to view the output run 'screen -R'" | tee -a logfile.txt

