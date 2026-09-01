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

#include <debug/SimBricksPciHost.hh>
#include <simbricks/pci_host.hh>

#include "base/cast.hh"
#include "base/intmath.hh"
#include "base/trace.hh"
#include "dev/pci/device.hh"
#include "dev/pci/pcireg.h"
#include "mem/packet_access.hh"
#include "sim/byteswap.hh"
#include "sim/system.hh"

namespace gem5 {
namespace simbricks {
namespace pci_host {

extern "C" {
#include <simbricks/pcie/if.h>

}

namespace {

/** PCI capability IDs we care about. */
constexpr uint8_t kCapIdMsi = 0x05;
constexpr uint8_t kCapIdMsix = 0x11;

/** Offset of the MSI-X part of the interrupt doorbell window. MSI shares a
 *  single dword at offset 0, MSI-X gets one dword per vector from here on. */
constexpr Addr kMsixDoorbellOff = 0x1000;

/** Bytes per MSI-X table entry (addr_lo, addr_hi, msg_data, vec_ctrl). */
constexpr Addr kMsixEntrySize = 16;

} // namespace

Host::Host(const Params &p)
    : PciHost(p),
      base::GenericBaseAdapter<SimbricksProtoPcieH2D, SimbricksProtoPcieD2H>::
          Interface(*this),
      adapter(*this, *this, p.sync),
      pioPort(name() + ".pio", *this),
      dmaPort(name() + ".dma", *this),
      system(*p.system),
      requestorId(p.system->getRequestorId(this)),
      sync(p.sync),
      confBase(p.conf_base),
      confSize(p.conf_size),
      confDeviceBits(p.conf_device_bits),
      busNum(p.bus_num),
      pciPioBase(p.pci_pio_base),
      pciMemBase(p.pci_mem_base),
      pciDmaBase(p.pci_dma_base),
      barMem32Base(p.bar_mem32_base),
      barMem64Base(p.bar_mem64_base),
      barIoBase(p.bar_io_base),
      doorbellAddr(p.intr_doorbell_addr),
      doorbellSize(p.intr_doorbell_size),
      programMsixTable(p.program_msix_table)
{
    DPRINTF(SimBricksPciHost, "simbricks-pci-host: adapter constructed\n");

    memset(&devIntro, 0, sizeof(devIntro));

    adapter.cfgSetPollInterval(p.poll_interval);

    /* A peer connecting before initState() waits in the listen backlog. */
    if (p.listen)
        adapter.listen(p.uxsocket_path, p.shm_path);
    else
        adapter.connect(p.uxsocket_path);
}

Host::~Host()
{
}

Port &
Host::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "pio")
        return pioPort;
    else if (if_name == "dma")
        return dmaPort;
    return PciHost::getPort(if_name, idx);
}

PciUpstream::DeviceInterface
Host::registerDevice(PciDevice *device, PciDevAddr dev_addr, PciIntPin pin)
{
    fatal_if(devAddr.has_value(),
             "%s: a SimBricks PCI host adapter represents a single device, "
             "but %02x:%02x.%i registered in addition to %02x:%02x.%i",
             name(), getBusNum(), dev_addr.dev, dev_addr.func,
             getBusNum(), devAddr ? devAddr->dev : 0,
             devAddr ? devAddr->func : 0);

    devAddr = dev_addr;
    return PciUpstream::registerDevice(device, dev_addr, pin);
}

void
Host::init()
{
    fatal_if(!pioPort.isConnected(), "Pio port of %s not connected!", name());
    fatal_if(!dmaPort.isConnected(), "Dma port of %s not connected!", name());

    PciUpstream::init();

    dmaPort.sendRangeChange();
}

void
Host::initState()
{
    PciHost::initState();

    /* Enumeration needs the ranges every responder advertises in init(), and
       registering needs the intro it builds. See Adapter::registerInit(). */
    enumerate();
    adapter.registerInit();
}

void
Host::startup()
{
    /* The peer asks us for the intro enumerate() built. */
    adapter.init();
    adapter.startup();

    PciHost::startup();
}

void
Host::serialize(CheckpointOut &cp) const
{
    PciHost::serialize(cp);
}

void
Host::unserialize(CheckpointIn &cp)
{
    PciHost::unserialize(cp);

    /* Restoring takes the place of initState(); enumeration is deterministic
       so it assigns what the checkpointed run assigned. */
    enumerate();
    adapter.registerInit();
}

AddrRange
Host::getConfigAddrRange() const
{
    return RangeSize(confBase, confSize);
}

AddrRange
Host::interfaceConfigRange(const PciDevAddr &dev_addr) const
{
    Addr bus_addr = (getBusNum() << 8) + (dev_addr.dev << 3) + dev_addr.func;

    return RangeSize(confBase + (bus_addr << confDeviceBits),
                     1 << confDeviceBits);
}

/******************************************************************************
 * Enumeration
 *
 * Nothing else here plays firmware, so the adapter does. The addresses it
 * assigns stay local -- the protocol only carries (bar, offset) pairs -- so
 * they just have to not collide within this instance.
 *****************************************************************************/

uint32_t
Host::cfgRead(Addr offset, unsigned size)
{
    uint8_t buf[sizeof(uint32_t)] = {0};

    panic_if(size != sizeof(uint8_t) && size != sizeof(uint16_t) &&
             size != sizeof(uint32_t),
             "cfgRead: invalid config access size %u", size);

    RequestPtr req = std::make_shared<Request>(
        devConfBase + offset, size, Request::UNCACHEABLE, requestorId);
    PacketPtr pkt = new Packet(req, MemCmd::ReadReq);
    pkt->dataStatic(buf);
    pioPort.sendFunctional(pkt);
    delete pkt;

    if (size == sizeof(uint8_t))
        return buf[0];

    if (size == sizeof(uint16_t)) {
        uint16_t value;
        memcpy(&value, buf, sizeof(value));
        return letoh(value);
    }

    uint32_t value;
    memcpy(&value, buf, sizeof(value));
    return letoh(value);
}

void
Host::cfgWrite(Addr offset, unsigned size, uint32_t value)
{
    uint8_t buf[sizeof(uint32_t)] = {0};

    switch (size) {
      case sizeof(uint8_t):
        buf[0] = value;
        break;
      case sizeof(uint16_t): {
        uint16_t tmp = htole((uint16_t)value);
        memcpy(buf, &tmp, sizeof(tmp));
        break;
      }
      case sizeof(uint32_t): {
        uint32_t tmp = htole(value);
        memcpy(buf, &tmp, sizeof(tmp));
        break;
      }
      default:
        panic("cfgWrite: invalid config access size %u", size);
    }

    RequestPtr req = std::make_shared<Request>(
        devConfBase + offset, size, Request::UNCACHEABLE, requestorId);
    PacketPtr pkt = new Packet(req, MemCmd::WriteReq);
    pkt->dataStatic(buf);
    pioPort.sendFunctional(pkt);
    delete pkt;
}

void
Host::enumerate()
{
    fatal_if(!devAddr.has_value(),
             "%s: no PCI device registered with this adapter", name());

    devConfBase = interfaceConfigRange(*devAddr).start();
    fatal_if(devConfBase == 0,
             "%s: config space of the device must not start at address 0",
             name());

    memset(&devIntro, 0, sizeof(devIntro));

    /* The values a BAR takes while being sized are meaningless, so make sure
       the device does not decode them. */
    cfgWrite(PCI_COMMAND, sizeof(uint16_t), 0);

    uint32_t id = cfgRead(PCI_VENDOR_ID, sizeof(uint32_t));
    devIntro.pci_vendor_id = id & 0xffff;
    devIntro.pci_device_id = id >> 16;

    uint32_t class_rev = cfgRead(PCI_REVISION_ID, sizeof(uint32_t));
    devIntro.pci_revision = class_rev & 0xff;
    devIntro.pci_progif = (class_rev >> 8) & 0xff;
    devIntro.pci_subclass = (class_rev >> 16) & 0xff;
    devIntro.pci_class = (class_rev >> 24) & 0xff;

    enumerateBars();
    enumerateCaps();

    /* The remote host's command register is its own -- its adapter answers
       config accesses locally -- so ours has to be on unconditionally. */
    cfgWrite(PCI_COMMAND, sizeof(uint16_t),
             PCI_CMD_IOSE | PCI_CMD_MSE | PCI_CMD_BME);

    inform("%s: %04x:%04x class %02x:%02x rev %02x, %u MSI / %u MSI-X vectors",
           name(), devIntro.pci_vendor_id, devIntro.pci_device_id,
           devIntro.pci_class, devIntro.pci_subclass, devIntro.pci_revision,
           devIntro.pci_msi_nvecs, devIntro.pci_msix_nvecs);
}

void
Host::enumerateBars()
{
    /* A 32-bit BAR would silently truncate an address from the 64-bit
       window, so it gets its own below 4 GiB. */
    Addr mem32_next = barMem32Base;
    Addr mem64_next = barMem64Base;
    Addr io_next = barIoBase;

    for (unsigned i = 0; i < SIMBRICKS_PROTO_PCIE_NBARS; i++) {
        Addr reg = PCI0_BASE_ADDR0 + i * sizeof(uint32_t);

        /* Standard sizing: write all ones, read back what the device left
           alone. gem5's PciBarNone and PciLegacyIoBar read back as zero, so
           they look unimplemented and stay hidden from the remote host. */
        cfgWrite(reg, sizeof(uint32_t), 0xffffffff);
        uint32_t probe = cfgRead(reg, sizeof(uint32_t));
        if (probe == 0) {
            cfgWrite(reg, sizeof(uint32_t), 0);
            continue;
        }

        uint64_t size;
        uint64_t flags;
        Addr raw;

        if (probe & 0x1) {
            /* IO BAR: bits [1:0] are fixed by hardware. */
            size = (~((uint64_t)(probe & ~0x3u)) + 1) & 0xffffffffULL;
            raw = roundUp(io_next, size);
            io_next = raw + size;
            fatal_if(io_next > 0x100000000ULL,
                     "%s: ran out of 32 bit IO space assigning BAR %u",
                     name(), i);

            flags = SIMBRICKS_PROTO_PCIE_BAR_IO;
            bars[i].addr = interfacePioAddr(*devAddr, raw);

            cfgWrite(reg, sizeof(uint32_t), (uint32_t)raw);
        } else {
            bool wide = ((probe >> 1) & 0x3) == 0x2;
            uint64_t mask = probe & ~0xfu;

            if (wide) {
                fatal_if(i + 1 >= SIMBRICKS_PROTO_PCIE_NBARS,
                         "%s: BAR %u is 64 bit but has no upper half",
                         name(), i);

                Addr reg_hi = reg + sizeof(uint32_t);
                cfgWrite(reg_hi, sizeof(uint32_t), 0xffffffff);
                mask |= ((uint64_t)cfgRead(reg_hi, sizeof(uint32_t))) << 32;
                size = ~mask + 1;
            } else {
                size = (~mask + 1) & 0xffffffffULL;
            }

            if (wide) {
                raw = roundUp(mem64_next, size);
                mem64_next = raw + size;
            } else {
                raw = roundUp(mem32_next, size);
                mem32_next = raw + size;
                fatal_if(mem32_next > 0x100000000ULL,
                         "%s: ran out of 32 bit memory space assigning BAR %u "
                         "(size %#llx); raise bar_mem32_base's window",
                         name(), i, size);
            }

            flags = 0;
            /* gem5's PciMemBar treats bit 3 as an address bit, so only a
               device decoding its own BARs ever sets this. */
            if ((probe >> 3) & 0x1)
                flags |= SIMBRICKS_PROTO_PCIE_BAR_PF;
            if (wide)
                flags |= SIMBRICKS_PROTO_PCIE_BAR_64;

            bars[i].addr = interfaceMemAddr(*devAddr, raw);

            cfgWrite(reg, sizeof(uint32_t), (uint32_t)raw);
            if (wide) {
                cfgWrite(reg + sizeof(uint32_t), sizeof(uint32_t),
                         (uint32_t)(raw >> 32));
            }
        }

        bars[i].size = size;
        bars[i].flags = flags;
        devIntro.bars[i].len = size;
        devIntro.bars[i].flags = flags;

        DPRINTF(SimBricksPciHost, "simbricks-pci-host: BAR %u size %#llx "
                "flags %#llx at %#llx\n", i, size, flags, bars[i].addr);

        if (flags & SIMBRICKS_PROTO_PCIE_BAR_64) {
            /* The upper half is not a BAR of its own on either side. */
            i++;
        }
    }
}

void
Host::enumerateCaps()
{
    unsigned off = cfgRead(PCI_CAP_PTR, sizeof(uint8_t)) & 0xfc;

    /* Bounded by the config header, but cap the count too: a broken device
       could produce a cycle. */
    for (unsigned n = 0; off >= PCI_DEVICE_SPECIFIC && off < PCI_CONFIG_SIZE &&
                         n < PCI_CONFIG_SIZE / 4; n++) {
        uint32_t hdr = cfgRead(off, sizeof(uint32_t));
        uint8_t cap_id = hdr & 0xff;
        uint16_t ctrl = hdr >> 16;

        if (cap_id == kCapIdMsi) {
            msiCapOff = off;
            msiNumVecs = 1u << ((ctrl >> 1) & 0x7);
            devIntro.pci_msi_nvecs = msiNumVecs;
        } else if (cap_id == kCapIdMsix) {
            msixCapOff = off;
            msixNumVecs = (ctrl & 0x7ff) + 1;

            uint32_t mtab = cfgRead(off + MSIXCAP_MTAB, sizeof(uint32_t));
            msixTableBar = mtab & 0x7;
            msixTableOff = mtab & ~0x7u;

            uint32_t mpba = cfgRead(off + MSIXCAP_MPBA, sizeof(uint32_t));

            devIntro.pci_msix_nvecs = msixNumVecs;
            devIntro.pci_msix_table_bar = msixTableBar;
            devIntro.pci_msix_table_offset = msixTableOff;
            devIntro.pci_msix_pba_bar = mpba & 0x7;
            devIntro.pci_msix_pba_offset = mpba & ~0x7u;
            devIntro.psi_msix_cap_offset = off;
        }

        unsigned next = (hdr >> 8) & 0xfc;
        if (next == off)
            break;
        off = next;
    }
}

/******************************************************************************
 * Interrupts
 *
 * INTx maps straight onto the PciUpstream interface the device already uses.
 *
 * MSI and MSI-X are memory writes, and the guest's writes to the MSI-X table
 * never cross the link -- the remote adapter emulates it -- so the device
 * would never learn a usable message address. The adapter therefore programs
 * the capability and the table itself, pointing every vector at a private
 * doorbell window, and turns writes landing there back into vector numbers.
 *****************************************************************************/

void
Host::sendInterrupt(uint8_t inttype, uint16_t vector)
{
    volatile union SimbricksProtoPcieD2H *msg = adapter.outAlloc();
    volatile struct SimbricksProtoPcieD2HInterrupt *intr = &msg->interrupt;

    intr->vector = vector;
    intr->inttype = inttype;
    adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_D2H_MSG_INTERRUPT);
}

void
Host::interfacePostInt(const PciDevAddr &dev_addr, PciIntPin pin)
{
    DPRINTF(SimBricksPciHost, "simbricks-pci-host: raising INTx\n");

    sendInterrupt(SIMBRICKS_PROTO_PCIE_INT_LEGACY_HI, 0);
}

void
Host::interfaceClearInt(const PciDevAddr &dev_addr, PciIntPin pin)
{
    DPRINTF(SimBricksPciHost, "simbricks-pci-host: lowering INTx\n");

    sendInterrupt(SIMBRICKS_PROTO_PCIE_INT_LEGACY_LO, 0);
}

void
Host::setupMsi()
{
    /* gem5 always lays out a 64-bit message address, so both halves can be
       written whatever the device claims. */
    cfgWrite(msiCapOff + MSICAP_MA, sizeof(uint32_t),
             (uint32_t)(doorbellAddr & ~0x3ULL));
    cfgWrite(msiCapOff + MSICAP_MUA, sizeof(uint32_t),
             (uint32_t)(doorbellAddr >> 32));
    cfgWrite(msiCapOff + MSICAP_MD, sizeof(uint16_t), 0);
    cfgWrite(msiCapOff + MSICAP_MMASK, sizeof(uint32_t), 0);

    uint16_t mc = cfgRead(msiCapOff + MSICAP_MC, sizeof(uint16_t));
    cfgWrite(msiCapOff + MSICAP_MC, sizeof(uint16_t), mc | 0x1);

    DPRINTF(SimBricksPciHost, "simbricks-pci-host: MSI enabled, %u vectors "
            "at doorbell %#llx\n", msiNumVecs, doorbellAddr);
}

void
Host::setupMsix()
{
    if (programMsixTable) {
        fatal_if(msixTableBar >= SIMBRICKS_PROTO_PCIE_NBARS ||
                 bars[msixTableBar].size == 0,
                 "%s: MSI-X table lives in unimplemented BAR %u", name(),
                 msixTableBar);

        for (unsigned v = 0; v < msixNumVecs; v++) {
            Addr entry = bars[msixTableBar].addr + msixTableOff +
                         v * kMsixEntrySize;
            Addr vec_addr = doorbellAddr + kMsixDoorbellOff +
                            v * sizeof(uint32_t);

            uint32_t fields[4] = {
                (uint32_t)vec_addr,          /* addr_lo */
                (uint32_t)(vec_addr >> 32),  /* addr_hi */
                v,                           /* msg_data */
                0                            /* vec_ctrl: unmasked */
            };

            for (unsigned w = 0; w < 4; w++) {
                uint32_t data = htole(fields[w]);
                RequestPtr req = std::make_shared<Request>(
                    entry + w * sizeof(uint32_t), sizeof(uint32_t),
                    Request::UNCACHEABLE, requestorId);
                PacketPtr pkt = new Packet(req, MemCmd::WriteReq);
                pkt->dataStatic(reinterpret_cast<uint8_t *>(&data));
                /* Functional: the guest's writes to this table cost no
                   simulated time here either. */
                pioPort.sendFunctional(pkt);
                delete pkt;
            }
        }
    }

    uint16_t mxc = cfgRead(msixCapOff + MSIXCAP_MXC, sizeof(uint16_t));
    cfgWrite(msixCapOff + MSIXCAP_MXC, sizeof(uint16_t), mxc | 0x8000);

    DPRINTF(SimBricksPciHost, "simbricks-pci-host: MSI-X enabled, %u vectors "
            "at doorbell %#llx\n", msixNumVecs,
            doorbellAddr + kMsixDoorbellOff);
}

bool
Host::handleDoorbell(PacketPtr pkt)
{
    Addr addr = pkt->getAddr() - pciDmaBase;

    if (addr < doorbellAddr || addr >= doorbellAddr + doorbellSize)
        return false;

    panic_if(!pkt->isWrite(),
             "%s: non-write access to the interrupt doorbell at %#llx",
             name(), addr);

    Addr off = addr - doorbellAddr;
    if (off >= kMsixDoorbellOff) {
        uint16_t vector = (off - kMsixDoorbellOff) / sizeof(uint32_t);

        DPRINTF(SimBricksPciHost,
                "simbricks-pci-host: MSI-X interrupt vector %u\n", vector);
        sendInterrupt(SIMBRICKS_PROTO_PCIE_INT_MSIX, vector);
    } else {
        /* The device replaces the low bits of the message data, programmed
           to 0 above, with the vector number. */
        uint64_t data = pkt->getUintX(ByteOrder::little);
        uint16_t vector = msiNumVecs > 1 ? data & (msiNumVecs - 1) : 0;

        DPRINTF(SimBricksPciHost,
                "simbricks-pci-host: MSI interrupt vector %u\n", vector);
        sendInterrupt(SIMBRICKS_PROTO_PCIE_INT_MSI, vector);
    }

    return true;
}

void
Host::devctrl(uint64_t flags)
{
    bool msi_en = !!(flags & SIMBRICKS_PROTO_PCIE_CTRL_MSI_EN);
    bool msix_en = !!(flags & SIMBRICKS_PROTO_PCIE_CTRL_MSIX_EN);

    DPRINTF(SimBricksPciHost, "simbricks-pci-host: devctrl flags %#llx\n",
            flags);

    /* INTx is deliberately not gated on SIMBRICKS_PROTO_PCIE_CTRL_INTX_EN:
       host adapters disagree on its polarity, and guessing wrong drops
       interrupts silently, whereas an unmasked one only costs a spurious
       interrupt. */

    if (msi_en != msiEnabled && msiCapOff) {
        if (msi_en) {
            setupMsi();
        } else {
            uint16_t mc = cfgRead(msiCapOff + MSICAP_MC, sizeof(uint16_t));
            cfgWrite(msiCapOff + MSICAP_MC, sizeof(uint16_t), mc & ~0x1);
        }
        msiEnabled = msi_en;
    }

    if (msix_en != msixEnabled && msixCapOff) {
        if (msix_en) {
            setupMsix();
        } else {
            uint16_t mxc = cfgRead(msixCapOff + MSIXCAP_MXC, sizeof(uint16_t));
            cfgWrite(msixCapOff + MSIXCAP_MXC, sizeof(uint16_t),
                     mxc & ~0x8000);
        }
        msixEnabled = msix_en;
    }
}

/******************************************************************************
 * SimBricks adapter interface
 *****************************************************************************/

size_t
Host::introOutPrepare(void *data, size_t maxlen)
{
    size_t introlen = sizeof(devIntro);
    assert(introlen <= maxlen);
    memcpy(data, &devIntro, introlen);
    return introlen;
}

void
Host::introInReceived(const void *data, size_t len)
{
    if (len < sizeof(struct SimbricksProtoPcieHostIntro))
        panic("introInReceived: intro short");
}

void
Host::initIfParams(SimbricksBaseIfParams &p)
{
    SimbricksPcieIfDefaultParams(&p);
    p.link_latency = params().link_latency;
    p.sync_interval = params().sync_tx_interval;
}

void
Host::handleInMsg(volatile union SimbricksProtoPcieH2D *msg)
{
    volatile struct SimbricksProtoPcieH2DRead *read;
    volatile struct SimbricksProtoPcieH2DWrite *write;
    volatile struct SimbricksProtoPcieH2DReadcomp *rc;
    volatile struct SimbricksProtoPcieH2DWritecomp *wc;
    DmaCompl *dc;
    uint64_t rid = 0, offset = 0;
    uint16_t len = 0;
    uint8_t bar = 0, ty;
    bool posted = false;

    ty = adapter.inType(msg);
    switch (ty) {
      case SIMBRICKS_PROTO_PCIE_H2D_MSG_READ:
        read = &msg->read;

        rid = read->req_id;
        offset = read->offset;
        len = read->len;
        bar = read->bar;
        DPRINTF(SimBricksPciHost, "simbricks-pci-host: received MMIO read "
                "id %lu bar %d offs %#llx size %u\n", rid, bar, offset, len);

        mmioReq(rid, bar, offset, len, true, false, nullptr);
        break;

      case SIMBRICKS_PROTO_PCIE_H2D_MSG_WRITE:
      case SIMBRICKS_PROTO_PCIE_H2D_MSG_WRITE_POSTED:
        write = &msg->write;

        rid = write->req_id;
        offset = write->offset;
        len = write->len;
        bar = write->bar;
        posted = ty == SIMBRICKS_PROTO_PCIE_H2D_MSG_WRITE_POSTED;
        DPRINTF(SimBricksPciHost, "simbricks-pci-host: received MMIO write "
                "id %lu bar %d offs %#llx size %u posted %d\n", rid, bar,
                offset, len, posted);

        mmioReq(rid, bar, offset, len, false, posted,
                (const void *)write->data);
        break;

      case SIMBRICKS_PROTO_PCIE_H2D_MSG_READCOMP:
        rc = &msg->readcomp;

        rid = rc->req_id;
        DPRINTF(SimBricksPciHost, "simbricks-pci-host: received DMA read "
                "completion id %lu\n", rid);

        dc = (DmaCompl *)(uintptr_t)rid;
        dc->pkt->setData((const uint8_t *)rc->data);
        dc->setDone();
        break;

      case SIMBRICKS_PROTO_PCIE_H2D_MSG_WRITECOMP:
        wc = &msg->writecomp;

        rid = wc->req_id;
        DPRINTF(SimBricksPciHost, "simbricks-pci-host: received DMA write "
                "completion id %lu\n", rid);

        dc = (DmaCompl *)(uintptr_t)rid;
        dc->setDone();
        break;

      case SIMBRICKS_PROTO_PCIE_H2D_MSG_DEVCTRL:
        devctrl(msg->devctrl.flags);
        break;

      default:
        panic("simbricks-pci-host: unsupported H2D message type=%x", ty);
    }

    adapter.inDone(msg);
}

/******************************************************************************
 * MMIO: remote host -> local device
 *****************************************************************************/

void
Host::mmioReq(uint64_t req_id, uint8_t bar, uint64_t offset, uint16_t len,
              bool is_read, bool posted, const void *data)
{
    panic_if(bar >= SIMBRICKS_PROTO_PCIE_NBARS || bars[bar].size == 0,
             "%s: MMIO access to unimplemented BAR %u", name(), bar);
    panic_if(offset > bars[bar].size || len > bars[bar].size - offset,
             "%s: MMIO access at offset %#llx size %u exceeds BAR %u",
             name(), offset, len, bar);

    RequestPtr req = std::make_shared<Request>(
        bars[bar].addr + offset, len, Request::UNCACHEABLE, requestorId);
    PacketPtr pkt =
        new Packet(req, is_read ? MemCmd::ReadReq : MemCmd::WriteReq);
    pkt->allocate();
    if (!is_read)
        memcpy(pkt->getPtr<uint8_t>(), data, len);
    pkt->pushSenderState(new MmioState(req_id, posted));

    if (!system.isTimingMode()) {
        pioPort.sendAtomic(pkt);
        mmioCompl(pkt);
        return;
    }

    mmioQueue.push_back(pkt);
    mmioSend();
}

void
Host::mmioSend()
{
    while (!mmioRetry && !mmioQueue.empty()) {
        PacketPtr pkt = mmioQueue.front();
        if (!pioPort.sendTimingReq(pkt)) {
            mmioRetry = true;
            break;
        }
        mmioQueue.pop_front();
    }
}

void
Host::mmioCompl(PacketPtr pkt)
{
    MmioState *state = safe_cast<MmioState *>(pkt->popSenderState());

    if (pkt->isRead()) {
        volatile union SimbricksProtoPcieD2H *msg = adapter.outAlloc();
        volatile struct SimbricksProtoPcieD2HReadcomp *rc = &msg->readcomp;

        rc->req_id = state->reqId;
        memcpy((void *)rc->data, pkt->getConstPtr<uint8_t>(), pkt->getSize());
        adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_D2H_MSG_READCOMP);
    } else if (!state->posted) {
        volatile union SimbricksProtoPcieD2H *msg = adapter.outAlloc();
        volatile struct SimbricksProtoPcieD2HWritecomp *wc = &msg->writecomp;

        wc->req_id = state->reqId;
        adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_D2H_MSG_WRITECOMP);
    }

    DPRINTF(SimBricksPciHost, "simbricks-pci-host: completed MMIO id %lu\n",
            state->reqId);

    delete state;
    delete pkt;
}

bool
HostPioPort::recvTimingResp(PacketPtr pkt)
{
    host.mmioCompl(pkt);
    return true;
}

void
HostPioPort::recvReqRetry()
{
    host.mmioRetry = false;
    host.mmioSend();
}

/******************************************************************************
 * DMA: local device -> remote host
 *****************************************************************************/

void
Host::dmaReq(DmaCompl &comp)
{
    Addr addr = comp.pkt->getAddr() - pciDmaBase;
    unsigned len = comp.pkt->getSize();

    volatile union SimbricksProtoPcieD2H *msg = adapter.outAlloc();

    if (comp.pkt->isRead()) {
        volatile struct SimbricksProtoPcieD2HRead *read = &msg->read;

        DPRINTF(SimBricksPciHost, "simbricks-pci-host: sending DMA read "
                "addr %#llx size %u id %lu\n", addr, len, (uint64_t)&comp);

        read->req_id = (uintptr_t)&comp;
        read->offset = addr;
        read->len = len;
        adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_D2H_MSG_READ);
    } else {
        volatile struct SimbricksProtoPcieD2HWrite *write = &msg->write;

        DPRINTF(SimBricksPciHost, "simbricks-pci-host: sending DMA write "
                "addr %#llx size %u id %lu\n", addr, len, (uint64_t)&comp);

        write->req_id = (uintptr_t)&comp;
        write->offset = addr;
        write->len = len;
        memcpy((void *)write->data, comp.pkt->getConstPtr<uint8_t>(), len);
        adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_D2H_MSG_WRITE);
    }
}

DevDmaPort::DevDmaPort(const std::string &_name, Host &_host, PortID _id)
    : QueuedResponsePort(_name, respQueue, _id), host(_host),
      respQueue(_host, *this)
{
}

AddrRangeList
DevDmaPort::getAddrRanges() const
{
    AddrRangeList ranges;
    ranges.push_back(AddrRange(0, MaxAddr));
    return ranges;
}

void
DevDmaPort::recvFunctional(PacketPtr pkt)
{
    panic_if(pkt->cacheResponding(),
             "DevDmaPort: should not see cache responding");

    if (respQueue.trySatisfyFunctional(pkt))
        return;

    recvAtomic(pkt);
}

Tick
DevDmaPort::recvAtomic(PacketPtr pkt)
{
    panic_if(pkt->cacheResponding(),
             "DevDmaPort: should not see cache responding");

    Tick receive_delay = pkt->headerDelay + pkt->payloadDelay;
    pkt->headerDelay = pkt->payloadDelay = 0;

    if (host.handleDoorbell(pkt)) {
        pkt->makeAtomicResponse();
        return receive_delay;
    }

    panic_if(host.sync, "simbricks-pci-host: atomic/functional DMA in "
             "synchronized mode");

    DmaCompl comp(pkt);
    host.dmaReq(comp);

    /* Nothing else can make progress meanwhile, so drive the adapter. */
    while (!comp.done)
        host.adapter.poll();

    pkt->makeAtomicResponse();
    return receive_delay + 1;
}

bool
DevDmaPort::recvTimingReq(PacketPtr pkt)
{
    panic_if(pkt->cacheResponding(),
             "DevDmaPort: should not see cache responding");

    if (host.handleDoorbell(pkt)) {
        if (pkt->needsResponse()) {
            pkt->makeTimingResponse();
            schedTimingResp(pkt, curTick() + 1);
        } else {
            pendingDelete.reset(pkt);
        }
        return true;
    }

    TimingDmaCompl *comp =
        new TimingDmaCompl(*this, pkt, pkt->needsResponse());
    comp->keep = true;
    host.dmaReq(*comp);
    if (comp->done)
        delete comp;
    else
        comp->keep = false;

    return true;
}

void
DevDmaPort::timingDmaCompl(TimingDmaCompl &comp)
{
    if (!comp.needResp) {
        if (comp.pkt && !comp.keep) {
            delete comp.pkt;
            comp.pkt = nullptr;
        }
        return;
    }

    comp.pkt->makeTimingResponse();
    schedTimingResp(comp.pkt, curTick());
    comp.pkt = nullptr;
}

TimingDmaCompl::TimingDmaCompl(DevDmaPort &_port, PacketPtr _pkt,
                               bool needResp_)
    : DmaCompl(_pkt), port(_port), needResp(needResp_), keep(false)
{
}

void
TimingDmaCompl::setDone()
{
    done = true;
    port.timingDmaCompl(*this);
    if (!keep)
        delete this;
}

} // namespace pci_host
} // namespace simbricks
} // namespace gem5
