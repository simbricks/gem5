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

#include <debug/SimBricksPci.hh>
#include <simbricks/pci.hh>

#include "base/trace.hh"

namespace gem5 {
namespace simbricks {
namespace pci {

extern "C" {
#include <simbricks/pcie/if.h>

}

Device::Device(const Params &p)
    : PciDevice(p),
    base::GenericBaseAdapter<SimbricksProtoPcieD2H, SimbricksProtoPcieH2D>::
        Interface(*this),
    adapter(*this, *this, p.sync),
    overridePort(name() + ".pio", *this),
    sync(p.sync),
    writesPosted(true)
{
    DPRINTF(SimBricksPci, "simbricks-pci: device constructed\n");

    adapter.cfgSetPollInterval(p.poll_interval);
    if (p.listen)
        adapter.listen(p.uxsocket_path, p.shm_path);
    else
        adapter.connect(p.uxsocket_path);
}

Device::~Device()
{
}

size_t
Device::introOutPrepare(void *data, size_t maxlen)
{
    size_t introlen = sizeof(struct SimbricksProtoPcieHostIntro);
    assert(introlen <= maxlen);
    memset(data, 0, introlen);
    return introlen;
}

void
Device::introInReceived(const void *data, size_t len)
{
    struct SimbricksProtoPcieDevIntro *di =
        (struct SimbricksProtoPcieDevIntro *) data;
    if (len < sizeof(*di))
        panic("introInReceived: intro short");

    config.vendor = di->pci_vendor_id;
    config.device = di->pci_device_id;
    config.revision = di->pci_revision;
    config.classCode = di->pci_class;
    config.subClassCode = di->pci_subclass;
    config.progIF = di->pci_progif;

    // fill in BAR details
    for (int i = 0; i < 6; i++) {
        if (di->bars[i].len > 0) {
            Bar *bar = getSimBricksBar(i);
            assert(bar != NULL);
            bar->setup(*this, i, di->bars[i].len,
                di->bars[i].flags);
        }
    }

    // Prepare MSI and MSI-X capabilities as needed (ugh)
    int cap_off = 64;
    uint8_t *next_ptr = nullptr;
    if (di->pci_msi_nvecs > 0) {
        MSICAP_BASE = cap_off;
        if (next_ptr)
            *next_ptr = MSICAP_BASE;
        else
            config.capabilityPtr = MSICAP_BASE;
        cap_off += sizeof(msicap);
        next_ptr = (((uint8_t *) &msicap) + 1);

        msicap.mid = 0x5;
        msicap.mc = 0x80;
        uint8_t x = 0;
        switch (di->pci_msi_nvecs) {
            case 1: x = 0; break;
            case 2: x = 1; break;
            case 4: x = 2; break;
            case 8: x = 3; break;
            case 16: x = 4; break;
            case 32: x = 5; break;
            default:
                panic("Invalid number of msi vectors");
        }
        msicap.mc |= (x << 1);
    }
    if (di->pci_msix_nvecs > 0) {
        MSIXCAP_BASE = cap_off;
        if (next_ptr)
            *next_ptr = MSIXCAP_BASE;
        else
            config.capabilityPtr = MSIXCAP_BASE;
        cap_off += sizeof(msixcap);
        next_ptr = ((uint8_t *) &msixcap + 1);

        msixcap.mxid = 0x11;
        msixcap.mxc = di->pci_msix_nvecs - 1;
        msixcap.mtab = di->pci_msix_table_offset | di->pci_msix_table_bar;
        msixcap.mpba = di->pci_msix_pba_offset | di->pci_msix_pba_bar;

        MSIXTable tmp1 = {{0UL,0UL,0UL,0UL}};
        msix_table.resize(di->pci_msix_nvecs , tmp1);
        MSIXPbaEntry tmp2 = {0};
        int pba_size = di->pci_msix_nvecs / MSIXVECS_PER_PBA;
        if ((di->pci_msix_nvecs % MSIXVECS_PER_PBA) > 0) {
            pba_size++;
        }
        msix_pba.resize(pba_size, tmp2);

        MSIX_TABLE_BAR = di->pci_msix_table_bar;
        MSIX_TABLE_OFFSET = di->pci_msix_table_offset;
        MSIX_TABLE_END = MSIX_TABLE_OFFSET +
                        di->pci_msix_nvecs * sizeof(MSIXTable);
        MSIX_PBA_BAR = di->pci_msix_pba_bar;
        MSIX_PBA_OFFSET = di->pci_msix_pba_offset;
        MSIX_PBA_END = MSIX_PBA_OFFSET +
                    ((di->pci_msix_nvecs + 1) / MSIXVECS_PER_PBA)
                    * sizeof(MSIXPbaEntry);
        if (((di->pci_msix_nvecs + 1) % MSIXVECS_PER_PBA) > 0) {
            MSIX_PBA_END += sizeof(MSIXPbaEntry);
        }
    }
}

void
Device::initIfParams(SimbricksBaseIfParams &p)
{
    SimbricksPcieIfDefaultParams(&p);
    p.link_latency = params().link_latency;
    p.sync_interval = params().sync_tx_interval;
}

ResponsePort
&Device::getPioPort()
{
    return overridePort;
}

void
Device::init()
{
    /* not calling parent init on purpose, as that will cause problems because
     * PIO port is not connected */
    if (!overridePort.isConnected())
        panic("Pio port (override) of %s not connected!", name());
    if (!dmaPort.isConnected())
        panic("DMA port (override) of %s not connected!", name());

    adapter.init();
    overridePort.sendRangeChange();
}

void
Device::readAsync(PciPioCompl &comp)
{
    int bar;
    Addr daddr;

    if (!getBAR(comp.pkt->getAddr(), bar, daddr)) {
        panic("Invalid PCI memory address\n");
    }

    DPRINTF(SimBricksPci, "simbricks-pci: sending read addr %x size %x "
            "id %lu bar %d offs %x\n",
            comp.pkt->getAddr(), comp.pkt->getSize(), (uint64_t) &comp,
            bar, daddr);

    if (readMsix(comp, daddr, bar))
        return;

    /* Send read message */
    volatile union SimbricksProtoPcieH2D *h2d_msg = adapter.outAlloc();
    volatile struct SimbricksProtoPcieH2DRead *read = &h2d_msg->read;
    read->req_id = (uintptr_t) &comp;
    read->offset = daddr;
    read->len = comp.pkt->getSize();
    read->bar = bar;
    adapter.outSend(h2d_msg, SIMBRICKS_PROTO_PCIE_H2D_MSG_READ);
}

void
Device::writeAsync(PciPioCompl &comp)
{
    int bar;
    Addr daddr;

    if (!getBAR(comp.pkt->getAddr(), bar, daddr)) {
        panic("Invalid PCI memory address\n");
    }

    DPRINTF(SimBricksPci, "simbricks-pci: sending write addr %x size %x "
            "id %lu bar %d offs %x\n",
            comp.pkt->getAddr(), comp.pkt->getSize(), (uint64_t) &comp,
            bar, daddr);

    if (writeMsix(comp, daddr, bar))
        return;

    /* Send write message */
    volatile union SimbricksProtoPcieH2D *h2d_msg = adapter.outAlloc();
    volatile struct SimbricksProtoPcieH2DWrite *write = &h2d_msg->write;
    write->req_id = (uintptr_t) &comp;
    write->offset = daddr;
    write->len = comp.pkt->getSize();
    write->bar = bar;
    memcpy((void *)write->data, comp.pkt->getPtr<uint8_t>(),
            comp.pkt->getSize());
    adapter.outSend(h2d_msg, SIMBRICKS_PROTO_PCIE_H2D_MSG_WRITE);
}

Tick
Device::read(PacketPtr pkt)
{
    PciPioCompl pc(pkt);

    if (sync)
        panic("simbricks-pci: atomic/functional read in synchronous mode");

    readAsync(pc);

    /* wait for operation to complete */
    while (!pc.done)
        adapter.poll();

    pkt->makeAtomicResponse();
    return 1;
}

Tick
Device::write(PacketPtr pkt)
{
    PciPioCompl pc(pkt);

    if (sync)
        panic("simbricks-pci: atomic/functional write in synchronous mode");

    writeAsync(pc);

    /* wait for operation to complete */
    while (!pc.done)
        adapter.poll();

    pkt->makeAtomicResponse();
    return 1;
}

Tick
Device::writeConfig(PacketPtr pkt)
{
    bool intx_before = !!(config.command & PCI_CMD_INTXDIS);
    bool msi_before = (msicap.mc & 0x1);
    bool msix_before = (msixcap.mxc & 0x8000);

    Tick t = PciDevice::writeConfig(pkt);

    bool intx_after = !!(config.command & PCI_CMD_INTXDIS);
    bool msi_after = (msicap.mc & 0x1);
    bool msix_after = (msixcap.mxc & 0x8000);

    /* send devctrl message if interrupt config changed */
    if (intx_before != intx_after || msi_before != msi_after ||
            msix_before != msix_after)
    {
        volatile union SimbricksProtoPcieH2D *msg = adapter.outAlloc();
        volatile struct SimbricksProtoPcieH2DDevctrl *devctrl = &msg->devctrl;

        devctrl->flags = 0;
        if (intx_after)
            devctrl->flags |= SIMBRICKS_PROTO_PCIE_CTRL_INTX_EN;
        if (msi_after)
            devctrl->flags |= SIMBRICKS_PROTO_PCIE_CTRL_MSI_EN;
        if (msix_after)
            devctrl->flags |= SIMBRICKS_PROTO_PCIE_CTRL_MSIX_EN;

        adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_H2D_MSG_DEVCTRL);
    }

    return t;
}

Device::DMACompl::DMACompl(Device *dev_, uint64_t id_, size_t bufsiz_,
        enum ctype ty_, const std::string &name_)
    : EventFunctionWrapper([this]{ done(); }, name_, true), dev(dev_), id(id_),
    ty(ty_), buf(new uint8_t[bufsiz_]), bufsiz(bufsiz_)
{
}

Device::DMACompl::~DMACompl()
{
    delete[] buf;
}

void
Device::DMACompl::done()
{
    dev->dmaDone(*this);
}

void
Device::dmaDone(DMACompl &comp)
{
    DPRINTF(SimBricksPci, "simbricks-pci: completed DMA id %u\n", comp.id);

    if (comp.ty == DMACompl::READ) {
        volatile union SimbricksProtoPcieH2D *msg = adapter.outAlloc();
        volatile struct SimbricksProtoPcieH2DReadcomp *rc;
        /* read completion */
        rc = &msg->readcomp;
        rc->req_id = comp.id;
        memcpy((void *) rc->data, comp.buf, comp.bufsiz);
        adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_H2D_MSG_READCOMP);
    } else if (comp.ty == DMACompl::WRITE) {
        volatile union SimbricksProtoPcieH2D *msg = adapter.outAlloc();
        volatile struct SimbricksProtoPcieH2DWritecomp *wc;
        /* write completion */
        wc = &msg->writecomp;
        wc->req_id = comp.id;
        adapter.outSend(msg, SIMBRICKS_PROTO_PCIE_H2D_MSG_WRITECOMP);
    } else if (comp.ty == DMACompl::MSI) {
        /* MSI interrupt */
    } else {
        panic("simbricks-pci: invalid completion");
    }
}

void
Device::handleInMsg(volatile union SimbricksProtoPcieD2H *msg)
{
    volatile struct SimbricksProtoPcieD2HRead *read;
    volatile struct SimbricksProtoPcieD2HWrite *write;
    volatile struct SimbricksProtoPcieD2HReadcomp *rc;
    volatile struct SimbricksProtoPcieD2HWritecomp *wc;
    volatile struct SimbricksProtoPcieD2HInterrupt *intr;
    DMACompl *dc;
    PciPioCompl *pc;
    uint64_t rid, addr, len;
    uint8_t ty;

    ty = adapter.inType(msg);
    switch (ty) {
        case SIMBRICKS_PROTO_PCIE_D2H_MSG_READ:
            /* Read */
            read = &msg->read;

            rid = read->req_id;
            addr = read->offset;
            len = read->len;
            DPRINTF(SimBricksPci, "simbricks-pci: received DMA read id %u "
                    "addr %x size %x\n", rid, addr, len);

            dc = new DMACompl(this, rid, len, DMACompl::READ, name());
            dmaRead(pciToDma(addr), len, dc, dc->buf, 0);
            break;

        case SIMBRICKS_PROTO_PCIE_D2H_MSG_WRITE:
            /* Write */
            write = &msg->write;

            rid = write->req_id;
            addr = write->offset;
            len = write->len;
            DPRINTF(SimBricksPci, "simbricks-pci: received DMA write id %u "
                    "addr %x size %x\n", rid, addr, len);

            dc = new DMACompl(this, rid, len, DMACompl::WRITE, name());
            memcpy(dc->buf, (void *) write->data, len);
            dmaWrite(pciToDma(addr), len, dc, dc->buf, 0);
            break;

        case SIMBRICKS_PROTO_PCIE_D2H_MSG_INTERRUPT:
            /* Interrupt */
            intr = &msg->interrupt;
            if (intr->inttype == SIMBRICKS_PROTO_PCIE_INT_MSI) {
                assert(intr->vector < 32);
                msi_signal(intr->vector);
            } else if (intr->inttype == SIMBRICKS_PROTO_PCIE_INT_MSIX) {
                msix_signal(intr->vector);
            } else if (intr->inttype == SIMBRICKS_PROTO_PCIE_INT_LEGACY_HI) {
                intrPost();
            } else if (intr->inttype == SIMBRICKS_PROTO_PCIE_INT_LEGACY_LO) {
                intrClear();
            } else {
                panic("unsupported inttype=0x%x", intr->inttype);
            }
            break;

        case SIMBRICKS_PROTO_PCIE_D2H_MSG_READCOMP:
            /* Receive read complete message */
            rc = &msg->readcomp;

            rid = rc->req_id;
            DPRINTF(SimBricksPci, "simbricks-pci: received read completion "
                    "id %lu\n", rid);

            pc = (PciPioCompl *) (uintptr_t) rid;
            pc->pkt->setData((const uint8_t *) rc->data);
            pc->setDone();
            break;

        case SIMBRICKS_PROTO_PCIE_D2H_MSG_WRITECOMP:
            /* Receive write complete message */
            wc = &msg->writecomp;

            rid = wc->req_id;
            DPRINTF(SimBricksPci, "simbricks-pci: received write completion "
                    "id %lu\n", rid);

            pc = (PciPioCompl *) (uintptr_t) rid;
            pc->setDone();
            break;

        default:
            panic("Simbricks::Pci::pollQueues: unsupported type=%x", ty);
    }

    adapter.inDone(msg);
}

void
Device::msi_signal(uint16_t vec)
{
    DMACompl *dc;

    DPRINTF(SimBricksPci, "simbricks-pci: received MSI intr vec %u\n", vec);

    if ((msicap.mc & 0x1) != 0 &&
            ((msicap.mmask & (1 << vec)) == 0))
    {
        DPRINTF(SimBricksPci, "simbricks-pci: MSI addr=%x val=%x mask=%x\n",
                msicap.ma, msicap.md, msicap.mmask);
        dc = new DMACompl(this, 0, 4, DMACompl::MSI, name());
        memcpy(dc->buf, &msicap.md, 2);
        memset(dc->buf + 2, 0, 2);

        dmaWrite(pciToDma(msicap.ma | ((uint64_t) msicap.mua << 32)),
                4, dc, dc->buf, 0);
    } else {
        DPRINTF(SimBricksPci, "simbricks-pci: MSI masked\n");
    }
}

void
Device::msix_signal(uint16_t vec)
{
    DMACompl *dc;
    MSIXTable &te = msix_table[vec];
    MSIXPbaEntry &pe = msix_pba[vec / MSIXVECS_PER_PBA];

    DPRINTF(SimBricksPci, "simbricks-pci: received MSI-X intr vec %u\n", vec);

    if ((te.fields.vec_ctrl & 1)) {
        warn("msix_signal(%u): TODO: masked", vec);

        pe.bits |= 1 << (vec % MSIXVECS_PER_PBA);
        return;
    }

    dc = new DMACompl(this, 0, 4, DMACompl::MSI, name());
    memcpy(dc->buf, &te.fields.msg_data, 4);

    uint64_t addr = te.fields.addr_hi;
    addr = (addr << 32) | te.fields.addr_lo;
    dmaWrite(pciToDma(addr), 4, dc, dc->buf, 0);
}

bool
Device::readMsix(PciPioCompl &comp, Addr addr, int bar)
{
    if (!MSIXCAP_BASE)
        return false;

    if (bar == MSIX_TABLE_BAR && addr >= MSIX_TABLE_OFFSET &&
            addr < MSIX_TABLE_END)
    {
        uint32_t off = addr - MSIX_TABLE_OFFSET;
        uint16_t idx = off / 16;
        uint8_t col = off % 16;
        MSIXTable &entry = msix_table[idx];

        assert(off % comp.pkt->getSize() == 0);

        comp.pkt->setData((const uint8_t *) entry.data + col);
        comp.setDone();
        return true;
    }

    if (bar == MSIX_PBA_BAR && addr >= MSIX_PBA_OFFSET &&
            addr < MSIX_PBA_END)
    {
        uint32_t off = addr - MSIX_PBA_OFFSET;
        uint16_t idx = off / (MSIXVECS_PER_PBA / 8);
        uint16_t col = off % (MSIXVECS_PER_PBA / 8);
        const MSIXPbaEntry &entry = msix_pba[idx];

        assert(off % comp.pkt->getSize() == 0);

        comp.pkt->setData(((const uint8_t *) &entry) + col);
        comp.setDone();
        return true;
    }

    return false;
}

bool
Device::writeMsix(PciPioCompl &comp, Addr addr, int bar)
{
    if (!MSIXCAP_BASE)
        return false;

    if (bar == MSIX_TABLE_BAR && addr >= MSIX_TABLE_OFFSET &&
            addr < MSIX_TABLE_END)
    {
        uint32_t off = addr - MSIX_TABLE_OFFSET;
        uint16_t idx = off / 16;
        uint8_t col = off % 16;
        MSIXTable &entry = msix_table[idx];

        assert(off % comp.pkt->getSize() == 0);

        memcpy((uint8_t *) entry.data + col, comp.pkt->getPtr<uint8_t>(),
                comp.pkt->getSize());
        comp.setDone();
        return true;
    }

    if (bar == MSIX_PBA_BAR && addr >= MSIX_PBA_OFFSET &&
            addr < MSIX_PBA_END)
    {
        uint32_t off = addr - MSIX_PBA_OFFSET;
        uint16_t idx = off / (MSIXVECS_PER_PBA / 8);
        uint16_t col = off % (MSIXVECS_PER_PBA / 8);
        MSIXPbaEntry &entry = msix_pba[idx];

        assert(off % comp.pkt->getSize() == 0);

        memcpy((uint8_t *) &entry + col, comp.pkt->getPtr<uint8_t>(),
                comp.pkt->getSize());
        comp.setDone();
        return true;
    }

    return false;
}

void
Device::serialize(CheckpointOut &cp) const
{
    PciDevice::serialize(cp);
}

void
Device::unserialize(CheckpointIn &cp)
{
    PciDevice::unserialize(cp);
}

void
Device::startup()
{
    adapter.startup();
}

Bar *
Device::getSimBricksBar(size_t i) const
{
    return dynamic_cast<Bar *>(BARs[i]);
}

/*****************************************************************************/

TimingPioPort::TimingPioPort(const std::string &_name,
              Device &_dev,
              PortID _id)
    : QueuedResponsePort(_name, respQueue, _id), dev(_dev),
    respQueue(_dev, *this)
{
}

AddrRangeList TimingPioPort::getAddrRanges() const
{
    return dev.getAddrRanges();
}


void
TimingPioPort::recvFunctional(PacketPtr pkt)
{
    if (pkt->cacheResponding())
        panic("TimingPioPort: should not see cache responding");


    if (respQueue.trySatisfyFunctional(pkt))
        return;

    if (pkt->isRead())
        dev.read(pkt);
    else
        dev.write(pkt);

    assert(pkt->isResponse() || pkt->isError());
}

Tick
TimingPioPort::recvAtomic(PacketPtr pkt)
{
    if (pkt->cacheResponding())
        panic("TimingPioPort: should not see cache responding");

    // Technically the packet only reaches us after the header delay,
    // and typically we also need to deserialise any payload.
    Tick receive_delay = pkt->headerDelay + pkt->payloadDelay;
    pkt->headerDelay = pkt->payloadDelay = 0;

    const Tick delay =
        pkt->isRead() ? dev.read(pkt) : dev.write(pkt);
    assert(pkt->isResponse() || pkt->isError());
    return delay + receive_delay;
}

bool
TimingPioPort::recvTimingReq(PacketPtr pkt)
{
    TimingPioCompl *tpc;
    bool needResp;

    if (pkt->cacheResponding())
        panic("TimingPioPort: should not see cache responding");

    needResp = pkt->needsResponse();

    if (pkt->isWrite() && dev.writesPosted)
        needResp = false;

    tpc = new TimingPioCompl(*this, pkt, needResp);
    if (pkt->isRead()) {
        dev.readAsync(*tpc);
    } else if (pkt->isWrite()) {
        tpc->keep = true;
        dev.writeAsync(*tpc);

        if (pkt->isWrite() && dev.writesPosted && pkt->needsResponse()) {
            DPRINTF(SimBricksPci, "simbricks-pci: sending immediate response "
                    "for posted write\n");
            pkt->makeTimingResponse();
            schedTimingResp(pkt, curTick() + 1);
            tpc->pkt = 0;
        }

        if (tpc->done)
            delete tpc;
        else
            tpc->keep = false;
    } else {
        panic("TimingPioPort: unknown packet type");
    }

    return true;
}

void
TimingPioPort::timingPioCompl(TimingPioCompl &comp)
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

TimingPioCompl::TimingPioCompl(TimingPioPort &_port, PacketPtr _pkt,
        bool needResp_)
    : PciPioCompl(_pkt), port(_port), needResp(needResp_), keep(false)
{
}

void
TimingPioCompl::setDone()
{
    done = true;
    port.timingPioCompl(*this);
    if (!keep)
        delete this;
}

} // namespace Pci
} // namespace Simbricks
} // namespace gem5
