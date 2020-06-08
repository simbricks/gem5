#include <debug/EthernetAll.hh>
#include <dev/net/cosim_nic.hh>

namespace Cosim {

Device::Device(const Params *p)
    : EtherDevBase(p), interface(nullptr)
{
    this->interface = new Interface(name() + ".int0", this);
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
