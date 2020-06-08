#include <debug/EthernetAll.hh>
#include <dev/net/cosim_nic.hh>
#include <dev/net/cosim_pcie_proto.h>

namespace Cosim {

Device::Device(const Params *p)
    : EtherDevBase(p), interface(nullptr), pci_fd(-1)
{
    printf("cosim: initialized\n");
    this->interface = new Interface(name() + ".int0", this);
    if (!nicsim_init(p)) {
        panic("cosim: failed to initialize cosim");
    }
}

Device::~Device()
{
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
    /*
    if (!uxsocket_init(p->uxsocket_path)) {
        return false;
    }

    struct cosim_pcie_dev_intro di;
    if (recv(this->pci_fd, &di, sizeof(di), 0) != sizeof(di)) {
        return false;
    }

    struct cosim_pcie_proto_host_intro hi;
    hi.flags = COSIM_PCIE_PROTO_FLAGS_HI_SYNC;
    if (send(this->pci_fd, &hi, sizeof(hi), 0) != sizeof(hi)) {
        return false;
    }
    */

    return true;
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
