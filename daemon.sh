#!/bin/bash

while :
do
    ./main.py 2>&1 >> logfile.txt
    echo "main.py exited with code $?. Restarting." | tee -a logfile.txt
done

