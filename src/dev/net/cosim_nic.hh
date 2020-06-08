#pragma once

#include <params/Cosim.hh>
#include <dev/net/etherpkt.hh>
#include <dev/net/etherdevice.hh>
#include <dev/net/etherint.hh>

namespace Cosim {

class Interface;
class Device : public EtherDevBase
{
public:
    typedef CosimParams Params;
    const Params *params() const {
        return dynamic_cast<const Params *>(_params);
    }

    Device(const Params *p);
    ~Device();

    virtual Port &getPort(const std::string &if_name,
                          PortID idx=InvalidPortID) override;

    virtual Tick read(PacketPtr pkt) override;
    virtual Tick write(PacketPtr pkt) override;

    virtual void serialize(CheckpointOut &cp) const override;
    virtual void unserialize(CheckpointIn &cp) override;

    bool recvPacket(EthPacketPtr pkt);
    void transferDone();

protected:
    Interface *interface;

private:
    bool nicsim_init(const Params *p);
    bool uxsocket_init(const char *path);

    int pciFd;
};

class Interface : public EtherInt
{
public:
    Interface(const std::string &name, Device *d)
        : EtherInt(name), dev(d)
    { }

    virtual bool recvPacket(EthPacketPtr pkt) override;
    virtual void sendDone();

private:
    Device *dev;
};

} // namespace Cosim
