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

#include "dev/storage/qcow2_disk_image.hh"

#include "base/logging.hh"
#include "base/trace.hh"
#include "debug/Qcow2.hh"

namespace gem5
{

Qcow2DiskImage::Qcow2DiskImage(const Params &p)
    : DiskImage(p),
      image(p.name, p.image_file, p.backing_search_path, p.l2_cache_size,
            p.max_chain_depth)
{
    if (!p.read_only) {
        fatal("%s: Qcow2DiskImage is read-only; stack a CowDiskImage on top "
              "of it to give the guest a writable disk.", name());
    }

    installTracing();
    image.open();
    initialized = true;

    /* DPRINTF already prefixes the SimObject name. */
    DPRINTF(Qcow2, "opened chain of %d layer(s):%s\n", image.depth(),
            image.chainDescription());
}

void
Qcow2DiskImage::installTracing()
{
    image.setDescendHook([this](size_t depth, const std::string &file,
                                uint64_t cluster, const char *why) {
        DPRINTF(Qcow2, "L%d %s: cluster %d %s, descending\n", depth, file,
                cluster, why);
    });
}

void
Qcow2DiskImage::notifyFork()
{
    /*
     * The child inherits the parent's descriptors. Reopen so the two
     * processes do not share file state, and drop the caches with them.
     */
    image.reopen();
}

std::streampos
Qcow2DiskImage::size() const
{
    return image.size() / SectorSize;
}

std::streampos
Qcow2DiskImage::read(uint8_t *data, std::streampos offset) const
{
    if (!initialized)
        panic("Qcow2DiskImage not initialized");

    image.readSector((uint64_t)offset * SectorSize, data);

    DPRINTF(Qcow2, "read: offset=%d\n", (uint64_t)offset);

    return SectorSize;
}

std::streampos
Qcow2DiskImage::write(const uint8_t *data, std::streampos offset)
{
    panic("%s: Qcow2DiskImage is read-only; stack a CowDiskImage on top of "
          "it to give the guest a writable disk.", name());
}

} // namespace gem5
