/*
 * Copyright 2026 Max Planck Institute for Software Systems,
 * National University of Singapore, and SimBricks UG (haftungsbeschränkt)
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

#ifndef __SIMBRICKS_PCI_HOST_HH__
#define __SIMBRICKS_PCI_HOST_HH__

#include <deque>
#include <optional>

#include "dev/pci/host.hh"
#include "dev/pci/types.hh"
#include "mem/qport.hh"
#include "params/SimBricksPciHost.hh"
#include "simbricks/base.hh"

namespace gem5 {

class System;

namespace simbricks {
namespace pci_host {
extern "C" {
#include <simbricks/pcie/proto.h>

}

class Host;

/**
 * Request port through which the adapter drives the local PCI hierarchy: the
 * config accesses of Host::enumerate(), and the MMIO arriving as H2D messages.
 */
class HostPioPort : public RequestPort
{
  protected:
    Host &host;

    bool recvTimingResp(PacketPtr pkt) override;
    void recvReqRetry() override;

  public:
    HostPioPort(const std::string &_name, Host &_host)
        : RequestPort(_name), host(_host)
    {}
};

/**
 * A DMA request received from the local device, in flight towards the remote
 * host.
 */
class DmaCompl
{
  public:
    PacketPtr pkt;
    bool done;

    DmaCompl(PacketPtr _pkt) : pkt(_pkt), done(false) {}
    virtual ~DmaCompl() {}

    virtual void
    setDone()
    {
        done = true;
    }
};

class DevDmaPort;
class TimingDmaCompl : public DmaCompl
{
  protected:
    DevDmaPort &port;

  public:
    bool needResp;
    bool keep;

    TimingDmaCompl(DevDmaPort &_port, PacketPtr _pkt, bool needResp_);
    virtual ~TimingDmaCompl() {}

    void setDone() override;
};

/**
 * Response port terminating the DMA traffic of the local device, which lands
 * here because nothing local claims host physical addresses. Requests become
 * D2H DMA messages, except writes into the doorbell window, which are MSI or
 * MSI-X and become D2H interrupt messages.
 */
class DevDmaPort : public QueuedResponsePort
{
  protected:
    Host &host;
    RespPacketQueue respQueue;
    std::unique_ptr<Packet> pendingDelete;

    void recvFunctional(PacketPtr pkt) override;
    Tick recvAtomic(PacketPtr pkt) override;
    bool recvTimingReq(PacketPtr pkt) override;

  public:
    DevDmaPort(const std::string &_name, Host &_host,
               PortID _id = InvalidPortID);
    virtual ~DevDmaPort() {}

    void timingDmaCompl(TimingDmaCompl &comp);

    AddrRangeList getAddrRanges() const override;
};

/**
 * SimBricks PCIe adapter for the device side of the protocol, the mirror image
 * of simbricks::pci::Device: it represents a remote host for a local gem5 PCI
 * device model (an AMD GPU, a NIC, ...), so the device can be simulated in its
 * own instance and attached to a host simulated elsewhere.
 *
 * In gem5 terms it is a PCI host, owning the enumeration, the BAR assignment
 * and the interrupt delivery. On the channel it sends the device intro and D2H
 * messages, and receives H2D ones.
 *
 * Two address spaces are involved: local addresses, which the adapter picks
 * when assigning BARs and translates the channel's (bar, offset) pairs into,
 * and DMA addresses, which are the remote host's physical addresses and pass
 * through unchanged (modulo pci_dma_base).
 */
class Host :
    public PciHost,
    public base::GenericBaseAdapter <SimbricksProtoPcieH2D,
                                     SimbricksProtoPcieD2H>::Interface
{
  public:
    PARAMS(SimBricksPciHost);

    Host(const Params &p);
    ~Host();

    Port &getPort(const std::string &if_name,
                  PortID idx = InvalidPortID) override;

    void init() override;
    void initState() override;
    void startup() override;

    PciUpstream::DeviceInterface registerDevice(PciDevice *device,
                                                PciDevAddr dev_addr,
                                                PciIntPin pin) override;

    void serialize(CheckpointOut &cp) const override;
    void unserialize(CheckpointIn &cp) override;

    friend class HostPioPort;
    friend class DevDmaPort;

  protected:
    /** @{ */
    /** SimBricks adapter interface */
    size_t introOutPrepare(void *data, size_t maxlen) override;
    void introInReceived(const void *data, size_t len) override;
    void handleInMsg(volatile SimbricksProtoPcieH2D *msg) override;
    void initIfParams(SimbricksBaseIfParams &p) override;
    /** @} */

    /** @{ */
    /** PciUpstream interface */
    AddrRange getConfigAddrRange() const override;
    AddrRange interfaceConfigRange(const PciDevAddr &dev_addr) const override;

    Addr
    interfacePioAddr(const PciDevAddr &dev_addr, Addr pci_addr) const override
    {
        return pciPioBase + pci_addr;
    }

    Addr
    interfaceMemAddr(const PciDevAddr &dev_addr, Addr pci_addr) const override
    {
        return pciMemBase + pci_addr;
    }

    Addr
    interfaceDmaAddr(const PciDevAddr &dev_addr, Addr pci_addr) const override
    {
        return pciDmaBase + pci_addr;
    }

    PciBusNum
    getBusNum() const override
    {
        return busNum;
    }

    void interfacePostInt(const PciDevAddr &dev_addr, PciIntPin pin) override;
    void interfaceClearInt(const PciDevAddr &dev_addr, PciIntPin pin) override;
    /** @} */

  private:
    /** State of one BAR, as discovered and assigned by enumerate(). */
    struct BarState
    {
        /** Size in bytes, 0 if the BAR is unused or the upper half of a
         *  64-bit BAR. */
        uint64_t size = 0;
        /** SIMBRICKS_PROTO_PCIE_BAR_* flags reported in the device intro. */
        uint64_t flags = 0;
        /** Local address the BAR was assigned to. */
        Addr addr = 0;
    };

    /** Sender state attached to the MMIO packets we inject, so that the
     *  completion can be matched back to the remote host's request. */
    class MmioState : public Packet::SenderState
    {
      public:
        uint64_t reqId;
        bool posted;

        MmioState(uint64_t req_id, bool posted_)
            : reqId(req_id), posted(posted_)
        {}
    };

    /** @{ */
    /** Config space access helpers. Functional: enumeration models what
     *  firmware did long before the simulation starts. */
    uint32_t cfgRead(Addr offset, unsigned size);
    void cfgWrite(Addr offset, unsigned size, uint32_t value);
    /** @} */

    /** Discover the local device's identity, size and assign its BARs, and
     *  locate its MSI/MSI-X capabilities. Fills in the device intro. */
    void enumerate();
    void enumerateBars();
    void enumerateCaps();

    /** Program the device's MSI capability / MSI-X table so that raising an
     *  interrupt turns into a write into the doorbell window. */
    void setupMsi();
    void setupMsix();

    /** Turn a doorbell write into a D2H interrupt message. Returns false if
     *  the access is not in the doorbell window. */
    bool handleDoorbell(PacketPtr pkt);

    void sendInterrupt(uint8_t inttype, uint16_t vector);

    /** @{ */
    /** MMIO requests from the remote host. */
    void mmioReq(uint64_t req_id, uint8_t bar, uint64_t offset, uint16_t len,
                 bool is_read, bool posted, const void *data);
    void mmioSend();
    void mmioCompl(PacketPtr pkt);
    /** @} */

    void dmaReq(DmaCompl &comp);
    void devctrl(uint64_t flags);

    base::GenericBaseAdapter
        <SimbricksProtoPcieH2D, SimbricksProtoPcieD2H> adapter;

    HostPioPort pioPort;
    DevDmaPort dmaPort;

    System &system;
    const RequestorID requestorId;

    const bool sync;

    const Addr confBase;
    const Addr confSize;
    const uint8_t confDeviceBits;
    const PciBusNum busNum;

    const Addr pciPioBase;
    const Addr pciMemBase;
    const Addr pciDmaBase;

    const Addr barMem32Base;
    const Addr barMem64Base;
    const Addr barIoBase;

    const Addr doorbellAddr;
    const Addr doorbellSize;
    const bool programMsixTable;

    /** The single device this adapter fronts, set by registerDevice(). */
    std::optional<PciDevAddr> devAddr;
    /** Local base address of the device's config space. */
    Addr devConfBase = 0;

    BarState bars[SIMBRICKS_PROTO_PCIE_NBARS];

    /** Device intro as reported to the remote host, built by enumerate(). */
    struct SimbricksProtoPcieDevIntro devIntro;

    /** Config space offsets of the MSI/MSI-X capabilities, 0 if absent. */
    unsigned msiCapOff = 0;
    unsigned msixCapOff = 0;
    /** Number of MSI vectors the device advertises. */
    unsigned msiNumVecs = 0;
    /** BAR and offset of the MSI-X table. */
    unsigned msixTableBar = 0;
    Addr msixTableOff = 0;
    unsigned msixNumVecs = 0;

    /** Interrupt modes the remote host has enabled through devctrl. */
    bool msiEnabled = false;
    bool msixEnabled = false;

    /** MMIO packets waiting for the PIO port to accept them. */
    std::deque<PacketPtr> mmioQueue;
    bool mmioRetry = false;
};

} // namespace pci_host
} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_PCI_HOST_HH__
