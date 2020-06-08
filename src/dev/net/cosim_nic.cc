#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <debug/EthernetAll.hh>
#include <dev/net/cosim_nic.hh>
#include <dev/net/cosim_pcie_proto.h>

namespace Cosim {

Device::Device(const Params *p)
    : EtherDevBase(p), interface(nullptr), pciFd(-1)
{
    this->interface = new Interface(name() + ".int0", this);
    if (!nicsim_init(p)) {
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
    printf("cosim: received read\n");
    DPRINTF(Ethernet, "cosim: receiving read addr %x size %x\n",
            pkt->getAddr(), pkt->getSize());
    pkt->setBadAddress();
    return 1;
}

Tick
Device::write(PacketPtr pkt)
{
    printf("cosim: received write\n");
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
Device::nicsim_init(const Params *p)
{
    if (!uxsocket_init(p->uxsocket_path.c_str())) {
        return false;
    }

    struct cosim_pcie_proto_dev_intro di;
    if (recv(this->pciFd, &di, sizeof(di), 0) != sizeof(di)) {
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
Device::uxsocket_init(const char *path)
{
    if ((this->pciFd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        goto error;
    }

    struct sockaddr_un saun;
    memset(&saun, 0, sizeof(saun));
    saun.sun_family = AF_UNIX;
    memcpy(saun.sun_path, path, strlen(path));

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
