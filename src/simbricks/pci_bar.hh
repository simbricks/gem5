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

#ifndef __SIMBRICKS_PCI_BAR_HH__
#define __SIMBRICKS_PCI_BAR_HH__

#include "dev/pci/device.hh"
#include "params/SimBricksPciBar.hh"

namespace gem5 {
namespace simbricks {
namespace pci {

class Device;

/* This is pretty ugly, but with the SimBricks PCI adapter we only know types
   and sizes of bars*/
class Bar : public PciBar
{
  protected:
    enum BarType
    {
        BarNone,
        BarIO,
        BarMem32,
        BarMem64L,
        BarMem64H,
    };

    Bar *lowerMem;
    BarType ty;
    uint64_t addr_raw;
    bool prefetchable;
    bool dummy;

  public:
    PARAMS(SimBricksPciBar);

    Bar(const Params &p);

    bool isIo() const override;
    bool isMem() const override;

    uint32_t write(const PciHost::DeviceInterface &host, uint32_t val)
        override;

    void setup(Device &dev, size_t idx, uint64_t len, uint64_t flags);
};

} // namespace pci
} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_PCI_BAR_HH__
