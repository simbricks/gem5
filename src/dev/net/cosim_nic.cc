#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <debug/EthernetAll.hh>
#include <dev/net/cosim_nic.hh>

namespace Cosim {


Device::Device(const Params *p)
    : EtherDevBase(p), interface(nullptr),
    overridePort(name() + ".pio", *this), sync(p->sync),
    pciAsynchrony(p->pci_asychrony),
    devLastTime(0),  pciFd(-1),
    d2hQueue(nullptr), d2hPos(0), d2hElen(0), d2hEnum(0),
    h2dQueue(nullptr), h2dPos(0), h2dElen(0), h2dEnum(0),
    pollEvent([this]{processPollEvent();}, name()),
    pollInterval(p->poll_interval)
{
    this->interface = new Interface(name() + ".int0", this);
    if (!nicsimInit(p)) {
        panic("cosim: failed to initialize cosim");
    }
    DPRINTF(Ethernet, "cosim: device configured\n");
    warn("pollInterval=%u  pciAsync=%u", pollInterval, pciAsynchrony);
}

Device::~Device()
{
    if (this->pciFd > 0) {
        close(this->pciFd);
    }
}

Port &
Device::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "interface") {
        return *this->interface;
    } else if (if_name == "pio") {
        return overridePort;
    }
    return EtherDevBase::getPort(if_name, idx);
}

SlavePort &Device::pciPioPort()
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
    overridePort.sendRangeChange();
}

void
Device::readAsync(PciPioCompl &comp)
{
    int bar;
    Addr daddr;

    DPRINTF(Ethernet, "cosim: receiving read addr %x size %x\n",
            comp.pkt->getAddr(), comp.pkt->getSize());

    if (!getBAR(comp.pkt->getAddr(), bar, daddr)) {
        panic("Invalid PCI memory address\n");
    }

    /* Send read message */
    volatile union cosim_pcie_proto_h2d *h2d_msg = h2dAlloc();
    volatile struct cosim_pcie_proto_h2d_read *read = &h2d_msg->read;
    read->req_id = (uintptr_t) &comp;
    read->offset = daddr;
    read->len = comp.pkt->getSize();
    read->bar = bar;
    read->own_type = COSIM_PCIE_PROTO_H2D_MSG_READ | COSIM_PCIE_PROTO_H2D_OWN_DEV;
}

void
Device::writeAsync(PciPioCompl &comp)
{
    int bar;
    Addr daddr;

    DPRINTF(Ethernet, "cosim: receiving write addr %x size %x\n",
            comp.pkt->getAddr(), comp.pkt->getSize());

    if (!getBAR(comp.pkt->getAddr(), bar, daddr)) {
        panic("Invalid PCI memory address\n");
    }

    /* Send write message */
    volatile union cosim_pcie_proto_h2d *h2d_msg = h2dAlloc();
    volatile struct cosim_pcie_proto_h2d_write *write = &h2d_msg->write;
    write->req_id = (uintptr_t) &comp;
    write->offset = daddr;
    write->len = comp.pkt->getSize();
    write->bar = bar;
    memcpy((void *)write->data, comp.pkt->getPtr<uint8_t>(),
            comp.pkt->getSize());
    write->own_type = COSIM_PCIE_PROTO_H2D_MSG_WRITE |
        COSIM_PCIE_PROTO_H2D_OWN_DEV;
}

Tick
Device::read(PacketPtr pkt)
{
    PciPioCompl pc(pkt);

    readAsync(pc);

    /* wait for operation to complete */
    while (!pc.done)
        pollQueues();

    pkt->makeAtomicResponse();
    return 1;
}

Tick
Device::write(PacketPtr pkt)
{
    PciPioCompl pc(pkt);

    writeAsync(pc);

    /* wait for operation to complete */
    while (!pc.done)
        pollQueues();

    pkt->makeAtomicResponse();
    return 1;
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
    DPRINTF(Ethernet, "cosim: completed DMA id %u\n", comp.id);

    if (comp.ty == DMACompl::READ) {
        volatile union cosim_pcie_proto_h2d *msg = h2dAlloc();
        volatile struct cosim_pcie_proto_h2d_readcomp *rc;
        /* read completion */
        rc = &msg->readcomp;
        rc->req_id = comp.id;
        memcpy((void *) rc->data, comp.buf, comp.bufsiz);
        rc->own_type = COSIM_PCIE_PROTO_H2D_MSG_READCOMP |
            COSIM_PCIE_PROTO_H2D_OWN_DEV;
    } else if (comp.ty == DMACompl::WRITE) {
        volatile union cosim_pcie_proto_h2d *msg = h2dAlloc();
        volatile struct cosim_pcie_proto_h2d_writecomp *wc;
        /* write completion */
        wc = &msg->writecomp;
        wc->req_id = comp.id;
        wc->own_type = COSIM_PCIE_PROTO_H2D_MSG_WRITECOMP |
            COSIM_PCIE_PROTO_H2D_OWN_DEV;
    } else if (comp.ty == DMACompl::MSI) {
        /* MSI interrupt */
    } else {
        panic("cosim: invalid completion");
    }
}

bool
Device::pollQueues()
{
    volatile struct cosim_pcie_proto_d2h_read *read;
    volatile struct cosim_pcie_proto_d2h_write *write;
    volatile struct cosim_pcie_proto_d2h_readcomp *rc;
    volatile struct cosim_pcie_proto_d2h_writecomp *wc;
    volatile struct cosim_pcie_proto_d2h_interrupt *intr;
    volatile struct cosim_pcie_proto_d2h_sync *sync;
    volatile union cosim_pcie_proto_d2h *msg;
    DMACompl *dc;
    PciPioCompl *pc;
    uint64_t rid, addr, len;
    uint8_t ty;

    msg = d2hPoll();
    if (!msg)
        return false;

    ty = msg->dummy.own_type & COSIM_PCIE_PROTO_D2H_MSG_MASK;
    switch (ty) {
        case COSIM_PCIE_PROTO_D2H_MSG_READ:
            /* Read */
            read = &msg->read;

            rid = read->req_id;
            addr = read->offset;
            len = read->len;
            DPRINTF(Ethernet, "cosim: received DMA read id %u addr %x "
                    "size %x\n", rid, addr, len);

            dc = new DMACompl(this, rid, len, DMACompl::READ, name());
            dmaRead(pciToDma(addr), len, dc, dc->buf, 0);
            break;

        case COSIM_PCIE_PROTO_D2H_MSG_WRITE:
            /* Write */
            write = &msg->write;

            rid = write->req_id;
            addr = write->offset;
            len = write->len;
            DPRINTF(Ethernet, "cosim: received DMA write id %u addr %x "
                    "size %x\n", rid, addr, len);

            dc = new DMACompl(this, rid, len, DMACompl::WRITE, name());
            memcpy(dc->buf, (void *) write->data, len);
            dmaWrite(pciToDma(addr), len, dc, dc->buf, 0);
            break;

        case COSIM_PCIE_PROTO_D2H_MSG_INTERRUPT:
            /* Interrupt */
            intr = &msg->interrupt;
            assert(intr->inttype == COSIM_PCIE_PROTO_INT_MSI);
            assert(intr->vector < 32);

            if ((msicap.mc & 0x1) != 0 &&
                    ((msicap.mmask & (1 << intr->vector)) == 0))
            {
                DPRINTF(Ethernet, "cosim: MSI addr=%x val=%x mask=%x\n",
                        msicap.ma, msicap.md, msicap.mmask);
                dc = new DMACompl(this, rid, 4, DMACompl::MSI, name());
                memcpy(dc->buf, &msicap.md, 2);
                memset(dc->buf + 2, 0, 2);

                dmaWrite(pciToDma(msicap.ma | ((uint64_t) msicap.mua << 32)),
                        4, dc, dc->buf, 0);
            } else {
                DPRINTF(Ethernet, "cosim: MSI masked\n");
            }
            break;

        case COSIM_PCIE_PROTO_D2H_MSG_READCOMP:
            /* Receive read complete message */
            rc = &msg->readcomp;
            pc = (PciPioCompl *) (uintptr_t) rc->req_id;
            pc->pkt->setData((const uint8_t *) rc->data);
            pc->setDone();
            break;

        case COSIM_PCIE_PROTO_D2H_MSG_WRITECOMP:
            /* Receive write complete message */
            wc = &msg->writecomp;
            pc = (PciPioCompl *) (uintptr_t) wc->req_id;
            pc->setDone();
            break;


        case COSIM_PCIE_PROTO_D2H_MSG_SYNC:
            /* received sync message */
            sync = &msg->sync;
            devLastTime = sync->timestamp;
            break;

        default:
            panic("Cosim::pollQueues: unsupported type=%x", ty);
    }

    d2hDone(msg);
    return true;
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
    schedule(this->pollEvent, curTick() + this->pollInterval);
}

bool
Device::recvPacket(EthPacketPtr pkt)
{
    DPRINTF(Ethernet, "cosim: receiving packet from wire\n");
    return true;
}

void
Device::transferDone()
{
    DPRINTF(Ethernet, "cosim: transfer complete\n");
}

bool
Device::nicsimInit(const Params *p)
{
    if (!uxsocketInit(p)) {
        return false;
    }

    struct cosim_pcie_proto_dev_intro di;
    if (recv(this->pciFd, &di, sizeof(di), 0) != sizeof(di)) {
        return false;
    }

    if (!queueCreate(p, di)) {
        return false;
    }

    struct cosim_pcie_proto_host_intro hi;
    hi.flags = (sync ? COSIM_PCIE_PROTO_FLAGS_HI_SYNC : 0);
    if (send(this->pciFd, &hi, sizeof(hi), 0) != sizeof(hi)) {
        return false;
    }

    if (sync && ((di.flags & COSIM_PCIE_PROTO_FLAGS_DI_SYNC) == 0))
        panic("Cosim::nicsimInit: sync offered by device does not match local "
                "setting");

    return true;
}

bool
Device::uxsocketInit(const Params *p)
{
    if ((this->pciFd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        goto error;
    }

    struct sockaddr_un saun;
    memset(&saun, 0, sizeof(saun));
    saun.sun_family = AF_UNIX;
    memcpy(saun.sun_path, p->uxsocket_path.c_str(), strlen(p->uxsocket_path.c_str()));

    if (connect(this->pciFd, (struct sockaddr *)&saun, sizeof(saun)) == -1) {
        goto error;
    }

    return true;

error:
    if (this->pciFd > 0) {
        close(this->pciFd);
    }
    return false;
}

bool
Device::queueCreate(const Params *p,
                    const struct cosim_pcie_proto_dev_intro &di)
{
    int fd = -1;
    if ((fd = open(p->shm_path.c_str(), O_RDWR)) == -1) {
        perror("Failed to open shm file");
        goto error;
    }

    void *addr;
    if ((addr = mmap(nullptr, 32 * 1024 * 1024, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_POPULATE, fd, 0)) == (void *)-1) {
        perror("mmap failed");
        goto error;
    }

    this->d2hQueue = (uint8_t *)addr + di.d2h_offset;
    this->d2hPos = 0;
    this->d2hElen = di.d2h_elen;
    this->d2hEnum = di.d2h_nentries;

    this->h2dQueue = (uint8_t *)addr + di.h2d_offset;
    this->h2dPos = 0;
    this->h2dElen = di.h2d_elen;
    this->h2dEnum = di.h2d_nentries;

    return true;

error:
    if (fd > 0) {
        close(fd);
    }
    return false;
}

volatile union cosim_pcie_proto_h2d *
Device::h2dAlloc()
{
    volatile union cosim_pcie_proto_h2d *msg =
        (volatile union cosim_pcie_proto_h2d *)
        (this->h2dQueue + this->h2dPos * this->h2dElen);

    if ((msg->dummy.own_type & COSIM_PCIE_PROTO_H2D_OWN_MASK) !=
            COSIM_PCIE_PROTO_H2D_OWN_HOST) {
        panic("cosim: failed to allocate h2d message\n");
    }

    this->h2dPos = (this->h2dPos + 1) % this->h2dEnum;
    return msg;
}

volatile union cosim_pcie_proto_d2h *
Device::d2hPoll()
{
    volatile union cosim_pcie_proto_d2h *msg;

    msg = (volatile union cosim_pcie_proto_d2h *)
        (this->d2hQueue + this->d2hPos * this->d2hElen);
    if ((msg->dummy.own_type & COSIM_PCIE_PROTO_D2H_OWN_MASK) ==
            COSIM_PCIE_PROTO_D2H_OWN_DEV) {
        return 0;
    }

    return msg;
}

void
Device::d2hDone(volatile union cosim_pcie_proto_d2h *msg)
{
    msg->dummy.own_type = (msg->dummy.own_type & COSIM_PCIE_PROTO_D2H_MSG_MASK) |
        COSIM_PCIE_PROTO_D2H_OWN_DEV;
    this->d2hPos = (this->d2hPos + 1) % this->d2hEnum;
}

void
Device::processPollEvent()
{
    if (sync) {
        // sync is enabled, first send pulse, then wait if necessary
        volatile union cosim_pcie_proto_h2d *msg = h2dAlloc();
        volatile struct cosim_pcie_proto_h2d_sync *sync = &msg->sync;

        sync->timestamp = curTick() + pciAsynchrony;
        sync->own_type = COSIM_PCIE_PROTO_H2D_MSG_SYNC |
            COSIM_PCIE_PROTO_H2D_OWN_DEV;

        while (devLastTime < curTick()) {
            //warn("waiting for PCI: last=%u cur=%u", devLastTime, curTick());
            pollQueues();
        }

    }
    //DPRINTF(Ethernet, "cosim: poll event: %u\n", curTick());
    while (pollQueues());

    schedule(this->pollEvent, curTick() + this->pollInterval);
}

bool
Interface::recvPacket(EthPacketPtr pkt)
{
    return this->dev->recvPacket(pkt);
}

void
Interface::sendDone()
{
    this->dev->transferDone();
}


/******************************************************************************/

TimingPioPort::TimingPioPort(const std::string &_name,
              Device &_dev,
              PortID _id)
    : QueuedSlavePort(_name, &_dev, respQueue, _id), dev(_dev),
    respQueue(_dev, *this)
{
}

AddrRangeList TimingPioPort::getAddrRanges() const
{
    warn("TimingPioPort::getAddrRanges()");
    return dev.getAddrRanges();
}


void TimingPioPort::recvFunctional(PacketPtr pkt)
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

Tick TimingPioPort::recvAtomic(PacketPtr pkt)
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

bool TimingPioPort::recvTimingReq(PacketPtr pkt)
{
    panic("TODO: TimingPioPort::recvTimingReq");
    return false;
}

} // namespace Cosim

Cosim::Device *
CosimParams::create()
{
    return new Cosim::Device(this);
}
