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
# two X86 systems. It is also uses the example
# dist gem5 bootscript util/dist/test/simple_bootscript.rcS that will
# run the linux ping command to check if we can see the peer system
# connected via the simulated Ethernet link.



GEM5_DIR=$(pwd)/../../..

IMG=$GEM5_DIR/../../../images/output-base/base.raw
VMLINUX=$GEM5_DIR/../../../images/vmlinux

FS_CONFIG=$GEM5_DIR/configs/simbricks/dist.py
SW_CONFIG=$GEM5_DIR/configs/dist/sw.py
GEM5_EXE=$GEM5_DIR/build/X86/gem5.fast

BOOT_SCRIPT=$GEM5_DIR/util/dist/test/cfg.client.0.tar
GEM5_DIST_SH=$GEM5_DIR/util/dist/gem5-dist.sh

X86_ARGS="--cpu-clock=3GHz --caches --l2cache --l3cache --l1d_size=32kB --l1i_size=32kB --l2_size=2MB --l3_size=32MB --l1d_assoc=8 --l1i_assoc=8 --l2_assoc=4 --l3_assoc=16 --cacheline_size=64 --ddio-enabled --ddio-way-part=8 --mem-type=DDR4_2400_16x4 "
NNODES=$1
LINK_DELAY="500ns" #500*1000 TICK == 500 nss
SYNC_DELAY="500ns"
OUT_DIR="$(pwd)/out/out-$NNODES"
CPU_TYPE="TimingSimpleCPU"
#CPU_TYPE="X86KvmCPU"
$GEM5_DIST_SH -n $NNODES                                                     \
                -r $OUT_DIR \
              -x $GEM5_EXE                                                   \
              -s $SW_CONFIG                                                  \
              -f $FS_CONFIG                                                  \
              --m5-args                                                      \
                 $DEBUG_FLAGS                                                \
              --fs-args   $X86_ARGS                                                   \
                  --cpu-type=$CPU_TYPE                                          \
		  --num-cpus=1                                               \
                  --disk-image=$IMG                                          \
                  --disk-image=$BOOT_SCRIPT         \
                  --kernel=$VMLINUX                                          \
              --cf-args --dist-sync-start=0t      --dist-sync-repeat=$SYNC_DELAY --ethernet-linkdelay=$LINK_DELAY                \
              $CHKPT_RESTORE