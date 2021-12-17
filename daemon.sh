#!/bin/bash

echo "Running main.py" | tee -a logfile.txt
while :
do
    ./main.py &>> logfile.txt
    echo "main.py exited with code $?. Restarting." | tee -a logfile.txt
done

