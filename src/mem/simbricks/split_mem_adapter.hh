#ifndef __SPLIT_MEM_ADAPTER_HH__
#define __SPLIT_MEM_ADAPTER_HH__

#include "mem/packet_queue.hh"
#include "mem/port.hh"
#include "mem/qport.hh"
#include "params/SplitMEMAdapter.hh"
#include "sim/sim_object.hh"
#include "simbricks/base.hh"

namespace simbricks {

extern "C" {
#include <simbricks/gem5_mem/proto.h>
}

class SplitMEMAdapter
    : public SimObject,
      public base::GenericBaseAdapter<SplitProtoC2M, SplitProtoM2C>::Interface {
 private:
  class MEMSidePort : public MasterPort {
   private:
    SplitMEMAdapter *owner;

   public:
    MEMSidePort(const std::string &name, SplitMEMAdapter *owner)
        : MasterPort(name, owner), owner(owner) {
    }
    // AddrRangeList getAddrRanges() const override;
    std::vector<PacketPtr> blockedPkt;

   protected:
    bool recvTimingResp(PacketPtr pkt) override;
    void recvReqRetry() override;
    //{panic("recvREqRetry no impl\n");}
    void recvRangeChange() override;
  };

  class IntRespProxyPort : public SlavePort {
   private:
    SplitMEMAdapter *owner;

   public:
    IntRespProxyPort(const std::string &name, SplitMEMAdapter *owner)
        : SlavePort(name, owner), owner(owner) {
    }
    AddrRangeList getAddrRanges() const override;
    AddrRangeList ranges_;

   protected:
    Tick recvAtomic(PacketPtr pkt) override {
      panic("recvAtomic unimpl\n");
    }

    void recvFunctional(PacketPtr pkt) override {
      panic("recvFunctional unimpl\n");
    }

    bool recvTimingReq(PacketPtr pkt) override {
      panic("recvTimingReq unimpl\n");
    }

    void recvRespRetry() override {
      panic("recvRespRetry unimpl\n");
    }
  };

  class IntReqProxyPort : public MasterPort {
   private:
    SplitMEMAdapter *owner;

   public:
    IntReqProxyPort(const std::string &name, SplitMEMAdapter *owner)
        : MasterPort(name, owner), owner(owner) {
    }

   protected:
    bool recvTimingResp(PacketPtr pkt) override {
      panic("recvTimingResp no impl\n");
    }
    void recvReqRetry() override {
      panic("recvREqRetry no impl\n");
    }
    void recvRangeChange() override;
    //{panic("recvRangeChange no impl\n");}
  };

  class PioProxyPort : public SlavePort {
   private:
    SplitMEMAdapter *owner;

   public:
    PioProxyPort(const std::string &name, SplitMEMAdapter *owner)
        : SlavePort(name, owner), owner(owner) {
    }
    AddrRangeList getAddrRanges() const override;
    AddrRangeList ranges_;

   protected:
    Tick recvAtomic(PacketPtr pkt) override {
      panic("recvAtomic unimpl\n");
    }

    void recvFunctional(PacketPtr pkt) override {
      panic("recvFunctional unimpl\n");
    }

    bool recvTimingReq(PacketPtr pkt) override {
      panic("recvTimingReq unimpl\n");
    }

    void recvRespRetry() override {
      panic("recvRespRetry unimpl\n");
    }
  };

  protected:
    base::GenericBaseAdapter<SplitProtoC2M, SplitProtoM2C> adapter;
    bool sync;

    virtual size_t introOutPrepare(void *data, size_t maxlen) override;
    virtual void introInReceived(const void *data, size_t len) override;
    virtual void initIfParams(SimbricksBaseIfParams &p) override;
    virtual void handleInMsg(volatile SplitProtoC2M *msg) override;


    bool handleResponse(PacketPtr pkt);

    volatile union SplitProtoM2C *m2cAlloc(bool syncAlloc = false,
                                           bool functional = false);
    void handleFunctional(PacketPtr pkt);
    AddrRangeList getAddrRanges() const;
    void sendRangeChange();
    void PktToMsg(PacketPtr pkt, volatile union SplitProtoM2C *msg,
                  uint8_t pkt_type);

    MEMSidePort mem_side;
    IntRespProxyPort int_resp_proxy;
    IntReqProxyPort int_req_proxy;
    PioProxyPort pio_proxy;


   public:
    typedef SplitMEMAdapterParams Params;
    const Params *params() const {
    return dynamic_cast<const Params *>(_params);
    }

    SplitMEMAdapter(const Params *params);
    virtual ~SplitMEMAdapter();
    void init() override;
    virtual void startup() override;
    Port &getPort(const std::string &if_name,
                  PortID idx = InvalidPortID) override;
};
} // namespace simbricks
#endif  //__SPLIT_MEM_ADAPTER_HH__
