/*
 * Copyright 2023 Max Planck Institute for Software Systems, and
 * National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <simbricks/pci_bar.hh>

#include "base/trace.hh"
#include "simbricks/pci.hh"

namespace gem5 {
namespace simbricks {
namespace pci {

extern "C" {
#include <simbricks/pcie/if.h>

}

Bar::Bar(const Params &p)
    : PciBar(p)
{
}

bool
Bar::isIo() const
{
    return ty == BarIO;
}

bool Bar::isMem() const
{
    return ty == BarMem32 || ty == BarMem64L || ty == BarMem64H;
}

uint32_t
Bar::write(const PciHost::DeviceInterface &host, uint32_t val)
{
    uint32_t bar = 0;

    switch (ty) {
        case BarNone:
            return 0;

        case BarIO:
            bar = val & ~(_size - 1);
            bar |= (1 << 0); // mark as IO bar
            _addr = host.pioAddr(bar & ~0x3);
            break;

        case BarMem32:
            bar = val & ~(_size - 1);
            if (prefetchable)
                bar |= 1 << 3;
            _addr = host.memAddr(bar & ~0xf);
            break;

        case BarMem64L:
            bar = val & ~(_size - 1);
            bar |= 1 << 2; // 64-bit bar
            if (prefetchable)
                bar |= 1 << 3;

            addr_raw &= (((1ULL << 32) - 1) << 32);
            addr_raw |= (bar & ~0xf);
            _addr = host.memAddr(addr_raw);
            break;

        case BarMem64H:
            bar = val & ~((_size - 1) >> 32);
            lowerMem->addr_raw &= (1ULL << 32) - 1;
            lowerMem->addr_raw |= val;
            lowerMem->_addr = host.memAddr(lowerMem->addr_raw);
            break;
    }

    return bar;
}

void
Bar::setup(Device &dev, size_t idx, uint64_t len, uint64_t flags)
{
    assert(len > 0);

    _size = len;
    dummy = !!(flags & SIMBRICKS_PROTO_PCIE_BAR_DUMMY);

    if ((flags & SIMBRICKS_PROTO_PCIE_BAR_IO)) {
        ty = BarIO;
    } else {
        ty = BarMem32;
        prefetchable = !!(flags & SIMBRICKS_PROTO_PCIE_BAR_PF);
        if ((flags & SIMBRICKS_PROTO_PCIE_BAR_64)) {
            ty = BarMem64L;

            Bar * upperMem = dev.getSimBricksBar(idx + 1);
            assert(upperMem != nullptr);
            upperMem->ty = BarMem64H;
            upperMem->lowerMem = this;
            upperMem->_size = 0;
        }
    }
}

} // namespace Pci
} // namespace Simbricks
} // namespace gem5
