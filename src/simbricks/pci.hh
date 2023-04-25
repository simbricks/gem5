/*
 * Copyright 2022 Max Planck Institute for Software Systems, and
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

#ifndef __SIMBRICKS_PCI_HH__
#define __SIMBRICKS_PCI_HH__

#include "dev/pci/device.hh"
#include "params/SimBricksPci.hh"
#include "simbricks/base.hh"
#include "simbricks/pci_bar.hh"

namespace gem5 {
namespace simbricks {
namespace pci {
extern "C" {
#include <simbricks/pcie/proto.h>

}

class PciPioCompl
{
  public:
    PacketPtr pkt;
    bool done;

    PciPioCompl(PacketPtr _pkt)
        : pkt(_pkt), done(false)
    {
    }

    virtual void setDone()
    {
        done = true;
    };
};

class TimingPioPort;
class TimingPioCompl : public PciPioCompl
{
  protected:
    TimingPioPort &port;

  public:
    bool needResp;
    bool keep;

    TimingPioCompl(TimingPioPort &_port, PacketPtr _pkt,
            bool needResp_);
    virtual ~TimingPioCompl() {}

    virtual void setDone() override;
};


class Device;
class TimingPioPort : public QueuedResponsePort
{
  protected:
    Device &dev;
    RespPacketQueue respQueue;
    std::unique_ptr<Packet> pendingDelete;

    virtual void recvFunctional(PacketPtr pkt);
    virtual Tick recvAtomic(PacketPtr pkt);
    virtual bool recvTimingReq(PacketPtr pkt);

  public:
    TimingPioPort(const std::string &_name,
                  Device &_dev,
                  PortID _id = InvalidPortID);
    virtual ~TimingPioPort() {}

    void timingPioCompl(TimingPioCompl &comp);

    virtual AddrRangeList getAddrRanges() const;
};

class Bar;
class Device :
    public PciDevice,
    public base::GenericBaseAdapter <SimbricksProtoPcieD2H,
                                     SimbricksProtoPcieH2D>::Interface
{
protected:
    // SimBricks base adapter
    base::GenericBaseAdapter
        <SimbricksProtoPcieD2H, SimbricksProtoPcieH2D> adapter;

    virtual size_t introOutPrepare(void *data, size_t maxlen) override;
    virtual void introInReceived(const void *data, size_t len) override;
    virtual void handleInMsg(volatile SimbricksProtoPcieD2H *msg) override;
    virtual void initIfParams(SimbricksBaseIfParams &p) override;

public:
    friend class TimingPioPort;


    PARAMS(SimBricksPci);

    Device(const Params &p);
    ~Device();

    void init() override;
    virtual ResponsePort &getPioPort() override;

    void msi_signal(uint16_t vec);
    void msix_signal(uint16_t vec);

    bool readMsix(PciPioCompl &comp, Addr addr, int bar);
    bool writeMsix(PciPioCompl &comp, Addr addr, int bar);

    void readAsync(PciPioCompl &comp);
    void writeAsync(PciPioCompl &comp);

    virtual Tick read(PacketPtr pkt) override;
    virtual Tick write(PacketPtr pkt) override;

    virtual Tick writeConfig(PacketPtr pkt) override;

    virtual void serialize(CheckpointOut &cp) const override;
    virtual void unserialize(CheckpointIn &cp) override;

    virtual void startup() override;

    // used by Bar class during setup
    Bar *getSimBricksBar(size_t i) const;
protected:
    TimingPioPort overridePort;

private:
    friend class DMACompl;
    class DMACompl : public EventFunctionWrapper
    {
        protected:
            Device *dev;

            void done();
        public:
            uint64_t id;
            enum ctype
            {
                READ,
                WRITE,
                MSI
            } ty;
            uint8_t *buf;
            size_t bufsiz;

            DMACompl(Device *dev_, uint64_t id_, size_t bufsiz_,
                     enum ctype ty_, const std::string &name);
            ~DMACompl();
    };

    bool sync;
    bool writesPosted;

    void dmaDone(DMACompl &comp);
};

} // namespace pci
} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_PCI_HH__
