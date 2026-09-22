/*
 * Copyright (c) 2026 The Regents of the University of California
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file
 * SimObject wrapper around the read-only qcow2 image reader.
 */

#ifndef __DEV_STORAGE_QCOW2_DISK_IMAGE_HH__
#define __DEV_STORAGE_QCOW2_DISK_IMAGE_HH__

#include "dev/storage/disk_image.hh"
#include "dev/storage/qcow2_image.hh"
#include "params/Qcow2DiskImage.hh"

namespace gem5
{

/**
 * Read-only accessor for a qcow2 image and its backing chain.
 *
 * All of the format handling lives in Qcow2Image; this class only adapts it
 * to the DiskImage interface. Guest writes are not supported: stack a
 * CowDiskImage on top of this object for those.
 */
class Qcow2DiskImage : public DiskImage
{
  public:
    typedef Qcow2DiskImageParams Params;
    Qcow2DiskImage(const Params &p);

    void notifyFork() override;

    /** Virtual size of the top overlay, in sectors. */
    std::streampos size() const override;

    std::streampos read(uint8_t *data, std::streampos offset) const override;
    std::streampos write(const uint8_t *data, std::streampos offset) override;

  private:
    /** Wire up Qcow2Image's descend hook to the Qcow2 debug flag. */
    void installTracing();

    Qcow2Image image;
};

} // namespace gem5

#endif // __DEV_STORAGE_QCOW2_DISK_IMAGE_HH__
