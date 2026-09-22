# Copyright (c) 2026 The Regents of the University of California
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

"""Selection of the right read-only DiskImage SimObject for a given file."""

from typing import List, Optional

from m5.objects import DiskImage, Qcow2DiskImage, RawDiskImage

# qcow2 magic, as defined by the format specification: "QFI\xfb".
QCOW2_MAGIC = b"QFI\xfb"


def disk_image_for(
    path: str,
    backing_search_path: Optional[List[str]] = None,
    **kwargs,
) -> DiskImage:
    """Return a read-only DiskImage of the appropriate type for ``path``.

    Only the leading magic number is inspected here, purely to pick a
    SimObject type. Everything else about a qcow2 image -- its version,
    feature bits, and backing chain -- is parsed in C++ by Qcow2DiskImage.
    Do not add header parsing to this function: a second parser that has to
    agree with the C++ one is exactly what the C++-side chain resolution was
    meant to avoid.

    :param path: Path to the disk image.
    :param backing_search_path: Directories searched by basename when a
        backing file recorded in an image header does not resolve. Ignored
        for raw images, which have no backing chain.
    """
    with open(path, "rb") as f:
        magic = f.read(len(QCOW2_MAGIC))

    if magic == QCOW2_MAGIC:
        return Qcow2DiskImage(
            image_file=path,
            backing_search_path=backing_search_path or [],
            **kwargs,
        )

    return RawDiskImage(image_file=path, read_only=True, **kwargs)
