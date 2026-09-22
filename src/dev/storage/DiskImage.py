# Copyright (c) 2005-2007 The Regents of The University of Michigan
# All rights reserved.
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

from m5.params import *
from m5.SimObject import SimObject


class DiskImage(SimObject):
    type = "DiskImage"
    abstract = True
    cxx_header = "dev/storage/disk_image.hh"
    cxx_class = "gem5::DiskImage"
    image_file = Param.String("disk image file")
    read_only = Param.Bool(False, "read only image")


class RawDiskImage(DiskImage):
    type = "RawDiskImage"
    cxx_header = "dev/storage/disk_image.hh"
    cxx_class = "gem5::RawDiskImage"


class CowDiskImage(DiskImage):
    type = "CowDiskImage"
    cxx_header = "dev/storage/disk_image.hh"
    cxx_class = "gem5::CowDiskImage"
    child = Param.DiskImage(RawDiskImage(read_only=True), "child image")
    table_size = Param.Int(65536, "initial table size")
    image_file = ""


class Qcow2DiskImage(DiskImage):
    type = "Qcow2DiskImage"
    cxx_header = "dev/storage/qcow2_disk_image.hh"
    cxx_class = "gem5::Qcow2DiskImage"

    # Read-only and expected be wrapped with a CowDiskImage for writes
    read_only = True

    backing_search_path = VectorParam.String(
        [],
        "Directories searched by basename when a backing file recorded in "
        "an image header does not resolve",
    )
    l2_cache_size = Param.MemorySize(
        "4MiB", "Total L2 table cache budget, shared across all chain layers"
    )
    max_chain_depth = Param.Int(
        16, "Backing chain depth limit; exceeding it is a fatal error"
    )
