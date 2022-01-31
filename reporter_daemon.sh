#!/bin/bash

echo "Running error_reporter.py" | tee -a logreport.txt
while :
do
    ./error_reporter.py &>> logreport.txt
    echo "error_reporter.py exited with code $?. Restarting." | tee -a logreport.txt
done

