#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#include <debug/EthernetAll.hh>
#include <dev/net/cosim_nic.hh>

namespace Cosim {

Device::Device(const Params *p)
    : EtherDevBase(p), interface(nullptr), pciFd(-1),
    d2hQueue(nullptr), d2hPos(0), d2hElen(0), d2hEnum(0),
    h2dQueue(nullptr), h2dPos(0), h2dElen(0), h2dEnum(0)
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
    DPRINTF(Ethernet, "cosim: receiving read addr %x size %x\n",
            pkt->getAddr(), pkt->getSize());
    pkt->setBadAddress();
    return 1;
}

Tick
Device::write(PacketPtr pkt)
{
    DPRINTF(Ethernet, "cosim: receiving write addr %x size %x\n",
            pkt->getAddr(), pkt->getSize());
    pkt->setBadAddress();
    return 1;
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
