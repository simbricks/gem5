#pragma once

#include <params/Cosim.hh>
#include <dev/net/etherpkt.hh>
#include <dev/net/etherdevice.hh>
#include <dev/net/etherint.hh>
#include <dev/net/cosim_pcie_proto.h>

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

    virtual void startup() override;

    bool recvPacket(EthPacketPtr pkt);
    void transferDone();

protected:
    Interface *interface;

private:
    bool h2dDone;
    PacketPtr h2dPacket;
    uint64_t h2dId;

    void pollQueues();
    bool nicsimInit(const Params *p);
    bool uxsocketInit(const Params *p);
    bool queueCreate(const Params *p,
                     const struct cosim_pcie_proto_dev_intro &di);
    volatile union cosim_pcie_proto_h2d *h2dAlloc();
    volatile union cosim_pcie_proto_d2h *d2hPoll();
    void d2hDone(volatile union cosim_pcie_proto_d2h *msg);
    void processPollEvent();

    int pciFd;
    uint64_t reqId;

    uint8_t *d2hQueue;
    size_t d2hPos;
    size_t d2hElen;
    size_t d2hEnum;

    uint8_t *h2dQueue;
    size_t h2dPos;
    size_t h2dElen;
    size_t h2dEnum;

    EventFunctionWrapper pollEvent;
    int pollInterval;
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
