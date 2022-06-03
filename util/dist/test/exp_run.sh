#! /bin/bash

sighandler(){
    echo "caught Interrup, aborting..."
    exit 1
}

trap "sighandler" SIGINT
bash run_x86.sh 8 > run-8.out
bash run_x86.sh 16 > run-16.out
bash run_x86.sh 32 > run-32.out
