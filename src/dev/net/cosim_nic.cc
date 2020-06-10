#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <debug/EthernetAll.hh>
#include <dev/net/cosim_nic.hh>

namespace Cosim {

static const int DEFAULT_POLL_INTERVAL = 100000000;

Device::Device(const Params *p)
    : EtherDevBase(p), interface(nullptr), h2dDone(false), h2dPacket(0),
    pciFd(-1), reqId(0),
    d2hQueue(nullptr), d2hPos(0), d2hElen(0), d2hEnum(0),
    h2dQueue(nullptr), h2dPos(0), h2dElen(0), h2dEnum(0),
    pollEvent([this]{processPollEvent();}, name()),
    pollInterval(DEFAULT_POLL_INTERVAL)
{
    this->interface = new Interface(name() + ".int0", this);
    if (!nicsimInit(p)) {
        panic("cosim: failed to initialize cosim");
    }
    DPRINTF(Ethernet, "cosim: device configured\n");
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
    }
    return EtherDevBase::getPort(if_name, idx);
}

Tick
Device::read(PacketPtr pkt)
{
    uint64_t req_id = this->reqId++;

    DPRINTF(Ethernet, "cosim: receiving read addr %x size %x\n",
            pkt->getAddr(), pkt->getSize());

    int bar;
    Addr daddr;
    if (!getBAR(pkt->getAddr(), bar, daddr)) {
        panic("Invalid PCI memory address\n");
    }

    assert(h2dPacket == 0);
    h2dDone = false;
    h2dPacket = pkt;
    h2dId = req_id;

    /* Send read message */
    volatile union cosim_pcie_proto_h2d *h2d_msg = h2dAlloc();
    volatile struct cosim_pcie_proto_h2d_read *read = &h2d_msg->read;
    read->req_id = req_id;
    read->offset = daddr;
    read->len = pkt->getSize();
    read->bar = bar;
    read->own_type = COSIM_PCIE_PROTO_H2D_MSG_READ | COSIM_PCIE_PROTO_H2D_OWN_DEV;

    /* wait for operation to complete */
    while (!h2dDone)
        pollQueues();

    pkt->makeAtomicResponse();
    h2dPacket = 0;
    return 1;
}

Tick
Device::write(PacketPtr pkt)
{
    uint64_t req_id = this->reqId++;

    DPRINTF(Ethernet, "cosim: receiving write addr %x size %x\n",
            pkt->getAddr(), pkt->getSize());

    int bar;
    Addr daddr;
    if (!getBAR(pkt->getAddr(), bar, daddr)) {
        panic("Invalid PCI memory address\n");
    }

    assert(h2dPacket == 0);
    h2dDone = false;
    h2dPacket = pkt;
    h2dId = req_id;

    /* Send write message */
    volatile union cosim_pcie_proto_h2d *h2d_msg = h2dAlloc();
    volatile struct cosim_pcie_proto_h2d_write *write = &h2d_msg->write;
    write->req_id = req_id;
    write->offset = daddr;
    write->len = pkt->getSize();
    write->bar = bar;
    memcpy((void *)write->data, pkt->getPtr<uint8_t>(), pkt->getSize());
    write->own_type = COSIM_PCIE_PROTO_H2D_MSG_WRITE | COSIM_PCIE_PROTO_H2D_OWN_DEV;

    /* wait for operation to complete */
    while (!h2dDone)
        pollQueues();

    pkt->makeAtomicResponse();
    h2dPacket = 0;
    return 1;
}

Device::DMACompl::DMACompl(Device *dev_, uint64_t id_, size_t bufsiz_,
        bool write_, const std::string &name_)
    : EventFunctionWrapper([this]{ done(); }, name_, true), dev(dev_), id(id_),
    write(write_), buf(new uint8_t[bufsiz_]), bufsiz(bufsiz_)
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
    volatile union cosim_pcie_proto_h2d *msg = h2dAlloc();
    volatile struct cosim_pcie_proto_h2d_readcomp *rc;
    volatile struct cosim_pcie_proto_h2d_writecomp *wc;

    DPRINTF(Ethernet, "cosim: completed DMA id %u\n", comp.id);

    if (!comp.write) {
        /* read completion */
        rc = &msg->readcomp;
        rc->req_id = comp.id;
        memcpy((void *) rc->data, comp.buf, comp.bufsiz);
        rc->own_type = COSIM_PCIE_PROTO_H2D_MSG_READCOMP |
            COSIM_PCIE_PROTO_H2D_OWN_DEV;
    } else {
        /* write completion */
        wc = &msg->writecomp;
        wc->req_id = comp.id;
        wc->own_type = COSIM_PCIE_PROTO_H2D_MSG_WRITECOMP |
            COSIM_PCIE_PROTO_H2D_OWN_DEV;
    }
}

bool
Device::pollQueues()
{
    volatile struct cosim_pcie_proto_d2h_read *read;
    volatile struct cosim_pcie_proto_d2h_write *write;
    volatile struct cosim_pcie_proto_d2h_readcomp *rc;
    volatile struct cosim_pcie_proto_d2h_writecomp *wc;
    volatile union cosim_pcie_proto_d2h *msg;
    DMACompl *dc;
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

            dc = new DMACompl(this, rid, len, false, name());
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

            dc = new DMACompl(this, rid, len, true, name());
            memcpy(dc->buf, (void *) write->data, len);
            dmaWrite(pciToDma(addr), len, dc, dc->buf, 0);
            break;

        case COSIM_PCIE_PROTO_D2H_MSG_INTERRUPT:
            /* Interrupt */
            warn("Cosim::pollQueues: TODO: interrupt");
            break;

        case COSIM_PCIE_PROTO_D2H_MSG_READCOMP:
            /* Receive read complete message */
            rc = &msg->readcomp;
            assert(rc->req_id == h2dId);
            h2dPacket->setData((const uint8_t *) rc->data);
            h2dDone = true;
            break;

        case COSIM_PCIE_PROTO_D2H_MSG_WRITECOMP:
            /* Receive write complete message */
            wc = &msg->writecomp;
            assert(wc->req_id == h2dId);
            h2dDone = true;
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
    schedule(this->pollEvent, this->pollInterval);
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
    hi.flags = COSIM_PCIE_PROTO_FLAGS_HI_SYNC;
    if (send(this->pciFd, &hi, sizeof(hi), 0) != sizeof(hi)) {
        return false;
    }

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

} // namespace Cosim

Cosim::Device *
CosimParams::create()
{
    return new Cosim::Device(this);
}
