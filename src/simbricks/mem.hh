/*
 * Copyright 2022 Max Planck Institute for Software Systems, and
 * National University of Singapore
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#ifndef __SIMBRICKS_MEM_HH__
#define __SIMBRICKS_MEM_HH__

#include "mem/qport.hh"
#include "params/SimBricksMem.hh"
#include "sim/sim_object.hh"
#include "simbricks/base.hh"

namespace gem5 {
namespace simbricks {
namespace mem {
extern "C" {
#include <simbricks/mem/proto.h>

}

class ReqCompl
{
  public:
    PacketPtr pkt;
    bool done;

    ReqCompl(PacketPtr _pkt)
        : pkt(_pkt), done(false)
    {
    }

    virtual void setDone()
    {
        done = true;
    };
};

class TimingMemPort;
class TimingReqCompl : public ReqCompl
{
  protected:
    TimingMemPort &port;

  public:
    bool needResp;
    bool keep;

    TimingReqCompl(TimingMemPort &_port, PacketPtr _pkt,
            bool needResp_);
    virtual ~TimingReqCompl() {}

    virtual void setDone() override;
};


class Adapter;
class TimingMemPort : public QueuedResponsePort
{
  protected:
    Adapter &adapter;
    RespPacketQueue respQueue;
    std::unique_ptr<Packet> pendingDelete;

    virtual void recvFunctional(PacketPtr pkt);
    virtual Tick recvAtomic(PacketPtr pkt);
    virtual bool recvTimingReq(PacketPtr pkt);

  public:
    TimingMemPort(const std::string &_name,
                  Adapter &_adapter,
                  PortID _id = InvalidPortID);
    virtual ~TimingMemPort() {}

    void timingReqCompl(TimingReqCompl &comp);

    virtual AddrRangeList getAddrRanges() const;
};


class Adapter :
    public SimObject,
    public base::GenericBaseAdapter <SimbricksProtoMemM2H,
                                     SimbricksProtoMemH2M>::Interface
{
protected:
    // SimBricks base adapter
    base::GenericBaseAdapter
        <SimbricksProtoMemM2H, SimbricksProtoMemH2M> adapter;

    virtual size_t introOutPrepare(void *data, size_t maxlen) override;
    virtual void introInReceived(const void *data, size_t len) override;
    virtual void handleInMsg(volatile SimbricksProtoMemM2H *msg) override;
    virtual void initIfParams(SimbricksBaseIfParams &p) override;

public:
    friend class TimingMemPort;

    PARAMS(SimBricksMem);

    Adapter(const Params &p);
    ~Adapter();

    virtual Port &getPort(const std::string &if_name,
                          PortID idx=InvalidPortID) override;

    void init() override;

    void readAsync(ReqCompl &comp);
    void writeAsync(ReqCompl &comp);

    Tick read(PacketPtr pkt);
    Tick write(PacketPtr pkt);

    virtual AddrRangeList getAddrRanges() const;

    virtual void serialize(CheckpointOut &cp) const override;
    virtual void unserialize(CheckpointIn &cp) override;

    virtual void startup() override;

protected:
    TimingMemPort port;

    bool sync;
    bool writesPosted;

    uint64_t staticASId;
    Addr baseAddress;
    Addr size;

};

} // namespace mem
} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_MEM_HH__
