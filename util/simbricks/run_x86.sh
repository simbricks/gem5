#! /bin/bash

#
# Copyright (c) 2015 ARM Limited
# All rights reserved
#
# The license below extends only to copyright in the software and shall
# not be construed as granting a license to any other intellectual
# property including but not limited to intellectual property relating
# to a hardware implementation of the functionality of the software
# licensed hereunder.  You may use the software subject to the license
# terms below provided that you ensure that this notice is replicated
# unmodified and in its entirety in all distributions of the software,
# modified or unmodified, in source code or in binary form.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# This is an example script to start a dist gem5 simulations using
# two AArch64 systems. It is also uses the example
# dist gem5 bootscript util/dist/test/simple_bootscript.rcS that will
# run the linux ping command to check if we can see the peer system
# connected via the simulated Ethernet link.

GEM5_DIR=$(pwd)/../..
REPO_DIR=$GEM5_DIR/../../..

IMG=$GEM5_DIR/../../../images/output-base/base.raw
VMLINUX=$GEM5_DIR/../../../images/vmlinux

FS_CONFIG=$GEM5_DIR/configs/simbricks/simbricks.py
GEM5_EXE=$GEM5_DIR/build/X86/gem5.fast
SWITCH_EXE=$REPO_DIR/sims/net/switch/net_switch

X86_ARGS="--cpu-clock=3GHz --cpu-type=TimingSimpleCPU --num-cpus=1 --caches --l2cache --l3cache --l1d_size=32kB --l1i_size=32kB --l2_size=2MB --l3_size=32MB --l1d_assoc=8 --l1i_assoc=8 --l2_assoc=4 --l3_assoc=16 --cacheline_size=64 --ddio-enabled --ddio-way-part=8 --mem-type=DDR4_2400_16x4 "
#X86_ARGS="--cpu-clock=3GHz --cpu-type=X86KvmCPU --num-cpus=1 --caches --l2cache --l3cache --l1d_size=32kB --l1i_size=32kB --l2_size=2MB --l3_size=32MB --l1d_assoc=8 --l1i_assoc=8 --l2_assoc=4 --l3_assoc=16 --cacheline_size=64 --ddio-enabled --ddio-way-part=8 --mem-type=DDR4_2400_16x4 "

NNODES=$1
LINK_DELAY=500 # 500 ns
SYNC_DELAY=500
SIMBRICKS_ARGS=""

ALL_PIDS=""
WAIT_PIDS=""
CUR_DIR=$(pwd)
RUN_DIR=$(pwd)/out/out-$1

#Args:
# - instance num
# - total size
run_gem5()
{
    echo "Starting gem5 instance $1"
    BOOT_SCRIPT=$RUN_DIR/guest/guest_$1/cfg.client.$1.tar
    SHM="$RUN_DIR/shm.$1"
    ETH="$RUN_DIR/eth.$1"
    CMD="--simbricks-eth-e1000=listen:$ETH:$SHM:latency=$LINK_DELAY:sync_interval=$SYNC_DELAY:sync"
    $GEM5_EXE --outdir=$RUN_DIR/m5out.$1\
                $DEBUG_FLAGS\
                $FS_CONFIG  \
                $X86_ARGS   \
                --disk-image=$IMG           \
                --disk-image=$BOOT_SCRIPT   \
                --kernel=$VMLINUX           \
                --dist-rank=$1              \
	            --dist-size=$NNODES         \
                $CMD >  $RUN_DIR/log.host$1 &
    pid=$!
    ALL_PIDS="$ALL_PIDS $pid"
    return $pid
}

run_switch()
{
    echo "Starting switch"
    args=""
    iface=0
    while [ $iface -lt $1 ]
    do
        args="$args -s $RUN_DIR/eth.$iface"
        ((iface++))
    done
    $SWITCH_EXE -S 500 -E 500 \
    $args > $RUN_DIR/log.switch &

    pid=$!
    ALL_PIDS="$ALL_PIDS $pid"
    #echo "switch pid = $pid"
    #wait $pid
}

# - total host num
make_script(){
    echo "make script for each host"
    let "bw=1000/($1-1)"
    counter=0
    while [ $counter -lt $1 ]
    do
        GUEST_TAR_DIR=$RUN_DIR/guest/guest_$counter/guest
        mkdir -p $GUEST_TAR_DIR
        echo "set -x"> $GUEST_TAR_DIR/run.sh
        echo "export HOME=/root" >> $GUEST_TAR_DIR/run.sh
        echo "export LANG=en_US" >> $GUEST_TAR_DIR/run.sh
        echo "export PATH=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games\"" >> $GUEST_TAR_DIR/run.sh
        MY_ADDR=$(($counter+2))
        if [ $MY_ADDR -lt 10 ]
        then
        MY_ADDR_PADDED=0${MY_ADDR}
        else
        MY_ADDR_PADDED=${MY_ADDR}
        fi
        
        echo "modprobe e1000" >> $GUEST_TAR_DIR/run.sh
        echo "ip link show" >> $GUEST_TAR_DIR/run.sh
        echo "ip link set dev eth0 address 00:90:00:00:00:${MY_ADDR_PADDED}" >> $GUEST_TAR_DIR/run.sh
        echo "ip link set dev eth0 up" >> $GUEST_TAR_DIR/run.sh
        echo "ip addr add 192.168.0.${MY_ADDR}/24 dev eth0" >> $GUEST_TAR_DIR/run.sh
        echo "echo \"Hello from $counter of $1\"" >> $GUEST_TAR_DIR/run.sh

        IS_SER=$(($counter%2))
        MY_ADDR_DEC=$(($MY_ADDR-1))

        if [ $IS_SER -eq 0 ]
        then
            echo "echo \"run iperf UDP server\"" >> $GUEST_TAR_DIR/run.sh
            echo "iperf -s -u -P 1" >> $GUEST_TAR_DIR/run.sh

            if [ $counter -eq 0 ]
            then
                echo "sleep 1" >> $GUEST_TAR_DIR/run.sh
                echo "/sbin/m5 exit" >> $GUEST_TAR_DIR/run.sh
            else
                echo "sleep 5" >> $GUEST_TAR_DIR/run.sh
            fi
        else
            echo "sleep 1" >> $GUEST_TAR_DIR/run.sh
            echo "iperf -c 192.168.0.${MY_ADDR_DEC} -i 1 -u -b 1000m" >> $GUEST_TAR_DIR/run.sh
            echo "sleep 5" >> $GUEST_TAR_DIR/run.sh
        fi
        chmod a+x $GUEST_TAR_DIR/run.sh
        cd $RUN_DIR/guest/guest_$counter
        tar -cvf cfg.client.$counter.tar guest/
        cd $CUR_DIR
        ((counter++))
    done

}

cleanup() {
    echo "Cleaning up"

    for p in $ALL_PIDS ; do
        kill -KILL $p &>/dev/null
    done
    date
}

sighandler(){
    echo "caught Interrup, aborting..."
    cleanup
    date
    exit 1
}

trap "sighandler" SIGINT
rm -rf $RUN_DIR
sleep 1
make_script $1
sleep 1
date
run_gem5 0 $1
child_pid=$! 
r=1
while [ $r -lt $1 ]
do
    run_gem5 $r $1
    ((r++))
done

sleep 15
run_switch $1

wait $child_pid
cleanup




