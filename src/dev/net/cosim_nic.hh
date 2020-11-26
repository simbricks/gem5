#pragma once

#include <params/Cosim.hh>
#include <dev/net/etherpkt.hh>
#include <dev/net/etherdevice.hh>
#include <dev/net/etherint.hh>
#include <dev/net/cosim_pcie_proto.h>

namespace Cosim {

class PciPioCompl {
  public:
    PacketPtr pkt;
    bool done;

    PciPioCompl(PacketPtr _pkt)
        : pkt(_pkt), done(false)
    {
    }

    virtual void setDone()
    {
        done = true;
    };
};

class TimingPioPort;
class TimingPioCompl : public PciPioCompl {
  protected:
    TimingPioPort &port;

  public:
    bool needResp;

    TimingPioCompl(TimingPioPort &_port, PacketPtr _pkt,
            bool needResp_);
    virtual ~TimingPioCompl() {}

    virtual void setDone() override;
};


class Device;
class TimingPioPort : public QueuedSlavePort
{
  protected:
    Device &dev;
    RespPacketQueue respQueue;
    std::unique_ptr<Packet> pendingDelete;

    virtual void recvFunctional(PacketPtr pkt);
    virtual Tick recvAtomic(PacketPtr pkt);
    virtual bool recvTimingReq(PacketPtr pkt);

  public:
    TimingPioPort(const std::string &_name,
                  Device &_dev,
                  PortID _id = InvalidPortID);
    virtual ~TimingPioPort() {}

    void timingPioCompl(TimingPioCompl &comp);

    virtual AddrRangeList getAddrRanges() const;
};



class Interface;
class Device : public EtherDevBase
{
public:
    friend class TimingPioPort;

    typedef CosimParams Params;
    const Params *params() const {
        return dynamic_cast<const Params *>(_params);
    }

    Device(const Params *p);
    ~Device();

    virtual Port &getPort(const std::string &if_name,
                          PortID idx=InvalidPortID) override;

    void init() override;
    virtual SlavePort &pciPioPort() override;

    void msi_signal(uint16_t vec);
    void msix_signal(uint16_t vec);

    bool readMsix(PciPioCompl &comp, Addr addr, int bar);
    bool writeMsix(PciPioCompl &comp, Addr addr, int bar);

    void readAsync(PciPioCompl &comp);
    void writeAsync(PciPioCompl &comp);

    virtual Tick read(PacketPtr pkt) override;
    virtual Tick write(PacketPtr pkt) override;

    virtual Tick writeConfig(PacketPtr pkt) override;

    virtual void serialize(CheckpointOut &cp) const override;
    virtual void unserialize(CheckpointIn &cp) override;

    virtual void startup() override;

    bool recvPacket(EthPacketPtr pkt);
    void transferDone();

protected:
    Interface *interface;
    TimingPioPort overridePort;

private:
    friend class DMACompl;
    class DMACompl : public EventFunctionWrapper
    {
        protected:
            Device *dev;

            void done();
        public:
            uint64_t id;
            enum ctype {
                READ,
                WRITE,
                MSI
            } ty;
            uint8_t *buf;
            size_t bufsiz;

            DMACompl(Device *dev_, uint64_t id_, size_t bufsiz_, enum ctype ty_,
                    const std::string &name);
            ~DMACompl();
    };

    bool sync;
    bool writesPosted;
    uint64_t pciAsynchrony;
    uint64_t devLastTime;

    void dmaDone(DMACompl &comp);
    bool pollQueues();
    bool nicsimInit(const Params *p);
    bool uxsocketInit(const Params *p);
    bool queueCreate(const Params *p,
                     const struct cosim_pcie_proto_dev_intro &di);
    volatile union cosim_pcie_proto_h2d *h2dAlloc(bool isSync=false);
    volatile union cosim_pcie_proto_d2h *d2hPoll();
    void d2hDone(volatile union cosim_pcie_proto_d2h *msg);
    void processPollEvent();
    void processSyncTxEvent();

    int pciFd;

    uint8_t *d2hQueue;
    size_t d2hPos;
    size_t d2hElen;
    size_t d2hEnum;

    uint8_t *h2dQueue;
    size_t h2dPos;
    size_t h2dElen;
    size_t h2dEnum;

    EventFunctionWrapper pollEvent;
    EventFunctionWrapper syncTxEvent;
    int pollInterval;
    int syncTxInterval;
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
