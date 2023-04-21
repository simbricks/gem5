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

#include <debug/AddrRanges.hh>
#include <debug/SimBricksMem.hh>
#include <simbricks/mem.hh>

#include "base/trace.hh"

namespace gem5 {
namespace simbricks {
namespace mem {

extern "C" {
#include <simbricks/mem/if.h>

}

Adapter::Adapter(const Params &p)
    : SimObject(p),
    base::GenericBaseAdapter<SimbricksProtoMemM2H, SimbricksProtoMemH2M>::
        Interface(*this),
    adapter(*this, *this, p.sync),
    port(name() + ".port", *this),
    sync(p.sync),
    writesPosted(true),
    staticASId(p.static_as_id),
    baseAddress(p.base_address),
    size(p.size)
{
    DPRINTF(SimBricksMem, "simbricks-mem: adapter constructed\n");

    adapter.cfgSetPollInterval(p.poll_interval);
    if (p.listen)
        adapter.listen(p.uxsocket_path, p.shm_path);
    else
        adapter.connect(p.uxsocket_path);
}

Adapter::~Adapter()
{
}

size_t
Adapter::introOutPrepare(void *data, size_t maxlen)
{
    size_t introlen = sizeof(struct SimbricksProtoMemHostIntro);
    assert(introlen <= maxlen);
    memset(data, 0, introlen);
    return introlen;
}

void
Adapter::introInReceived(const void *data, size_t len)
{
    struct SimbricksProtoMemMemIntro *mi =
        (struct SimbricksProtoMemMemIntro *) data;
    if (len < sizeof(*mi))
        panic("introInReceived: intro short");
}

void
Adapter::initIfParams(SimbricksBaseIfParams &p)
{
    SimbricksMemIfDefaultParams(&p);
    p.link_latency = params().link_latency;
    p.sync_interval = params().sync_tx_interval;
}

Port &
Adapter::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "port") {
        return port;
    }
    return SimObject::getPort(if_name, idx);
}


void
Adapter::init()
{
    if (!port.isConnected())
        panic("Port of %s not connected!", name());

    adapter.init();
    port.sendRangeChange();
    SimObject::init();
}

void
Adapter::readAsync(ReqCompl &comp)
{
    DPRINTF(SimBricksMem, "simbricks-mem: sending read addr %x size %x "
            "id %lu\n",
            comp.pkt->getAddr(), comp.pkt->getSize(), (uint64_t) &comp);

    /* Send read message */
    volatile union SimbricksProtoMemH2M *h2d_msg = adapter.outAlloc();
    volatile struct SimbricksProtoMemH2MRead *read = &h2d_msg->read;
    read->req_id = (uintptr_t) &comp;
    read->addr = comp.pkt->getAddr() - baseAddress;
    read->len = comp.pkt->getSize();
    read->as_id = staticASId;
    adapter.outSend(h2d_msg, SIMBRICKS_PROTO_MEM_H2M_MSG_READ);
}

void
Adapter::writeAsync(ReqCompl &comp)
{
    DPRINTF(SimBricksMem,
            "simbricks-mem: sending write addr %x size %x id %lu\n",
            comp.pkt->getAddr(), comp.pkt->getSize(), (uint64_t) &comp);

    /* Send write message */
    volatile union SimbricksProtoMemH2M *h2d_msg = adapter.outAlloc();
    volatile struct SimbricksProtoMemH2MWrite *write = &h2d_msg->write;
    write->req_id = (uintptr_t) &comp;
    write->addr = comp.pkt->getAddr() - baseAddress;
    write->len = comp.pkt->getSize();
    write->as_id = staticASId;
    memcpy((void *)write->data, comp.pkt->getPtr<uint8_t>(),
            comp.pkt->getSize());
    adapter.outSend(h2d_msg, SIMBRICKS_PROTO_MEM_H2M_MSG_WRITE);
}

Tick
Adapter::read(PacketPtr pkt)
{
    ReqCompl pc(pkt);

    if (sync)
        panic("simbricks-mem: atomic/functional read in synchronized mode");

    readAsync(pc);

    /* wait for operation to complete */
    while (!pc.done)
        adapter.poll();

    pkt->makeAtomicResponse();
    return 1;
}

Tick
Adapter::write(PacketPtr pkt)
{
    ReqCompl pc(pkt);

    if (sync)
        panic("simbricks-mem: atomic/functional write in synchronized mode");

    writeAsync(pc);

    /* wait for operation to complete */
    while (!pc.done)
        adapter.poll();

    pkt->makeAtomicResponse();
    return 1;
}

void
Adapter::handleInMsg(volatile union SimbricksProtoMemM2H *msg)
{
    volatile struct SimbricksProtoMemM2HReadcomp *rc;
    volatile struct SimbricksProtoMemM2HWritecomp *wc;
    ReqCompl *pc;
    uint64_t rid;
    uint8_t ty;

    ty = adapter.inType(msg);
    switch (ty) {
        case SIMBRICKS_PROTO_MEM_M2H_MSG_READCOMP:
            /* Receive read complete message */
            rc = &msg->readcomp;

            rid = rc->req_id;
            DPRINTF(SimBricksMem, "simbricks-mem: received read completion "
                    "id %lu\n", rid);

            pc = (ReqCompl *) (uintptr_t) rid;
            pc->pkt->setData((const uint8_t *) rc->data);
            pc->setDone();
            break;

        case SIMBRICKS_PROTO_MEM_M2H_MSG_WRITECOMP:
            /* Receive write complete message */
            wc = &msg->writecomp;

            rid = wc->req_id;
            DPRINTF(SimBricksMem, "simbricks-mem: received write completion "
                    "id %lu\n", rid);

            pc = (ReqCompl *) (uintptr_t) rid;
            pc->setDone();
            break;

        default:
            panic("Simbricks::Pci::pollQueues: unsupported type=%x", ty);
    }

    adapter.inDone(msg);
}

AddrRangeList
Adapter::getAddrRanges() const
{
    AddrRangeList ranges;
    DPRINTF(AddrRanges, "registering range: %#x-%#x\n", baseAddress, size);
    ranges.push_back(RangeSize(baseAddress, size));
    return ranges;
}

void
Adapter::serialize(CheckpointOut &cp) const
{
    SimObject::serialize(cp);
}

void
Adapter::unserialize(CheckpointIn &cp)
{
    SimObject::unserialize(cp);
}

void
Adapter::startup()
{
    adapter.startup();
}


/*****************************************************************************/

TimingMemPort::TimingMemPort(const std::string &_name,
              Adapter &_adapter,
              PortID _id)
    : QueuedResponsePort(_name, respQueue, _id), adapter(_adapter),
    respQueue(_adapter, *this)
{
}

AddrRangeList TimingMemPort::getAddrRanges() const
{
    return adapter.getAddrRanges();
}


void
TimingMemPort::recvFunctional(PacketPtr pkt)
{
    if (pkt->cacheResponding())
        panic("TimingMemPort: should not see cache responding");


    if (respQueue.trySatisfyFunctional(pkt))
        return;

    if (pkt->isRead())
        adapter.read(pkt);
    else
        adapter.write(pkt);

    assert(pkt->isResponse() || pkt->isError());
}

Tick
TimingMemPort::recvAtomic(PacketPtr pkt)
{
    if (pkt->cacheResponding())
        panic("TimingMemPort: should not see cache responding");

    // Technically the packet only reaches us after the header delay,
    // and typically we also need to deserialise any payload.
    Tick receive_delay = pkt->headerDelay + pkt->payloadDelay;
    pkt->headerDelay = pkt->payloadDelay = 0;

    const Tick delay =
        pkt->isRead() ? adapter.read(pkt) : adapter.write(pkt);
    assert(pkt->isResponse() || pkt->isError());
    return delay + receive_delay;
}

bool
TimingMemPort::recvTimingReq(PacketPtr pkt)
{
    TimingReqCompl *tpc;
    bool needResp;

    if (pkt->cacheResponding())
        panic("TimingMemPort: should not see cache responding");

    needResp = pkt->needsResponse();

    if (pkt->isWrite() && adapter.writesPosted)
        needResp = false;

    tpc = new TimingReqCompl(*this, pkt, needResp);
    if (pkt->isRead()) {
        adapter.readAsync(*tpc);
    } else if (pkt->isWrite()) {
        tpc->keep = true;
        adapter.writeAsync(*tpc);

        if (pkt->isWrite() && adapter.writesPosted && pkt->needsResponse()) {
            DPRINTF(SimBricksMem, "simbricks-mem: sending immediate response "
                    "for posted write\n");
            pkt->makeTimingResponse();
            schedTimingResp(pkt, curTick() + 1);
            tpc->pkt = 0;
        }

        if (tpc->done)
            delete tpc;
        else
            tpc->keep = false;
    } else {
        panic("TimingMemPort: unknown packet type");
    }

    return true;
}

void
TimingMemPort::timingReqCompl(TimingReqCompl &comp)
{
    if (!comp.needResp) {
        if (comp.pkt && !comp.keep) {
            delete comp.pkt;
            comp.pkt = nullptr;
        }
        return;
    }

    comp.pkt->makeTimingResponse();
    schedTimingResp(comp.pkt, curTick());
    comp.pkt = nullptr;
}

TimingReqCompl::TimingReqCompl(TimingMemPort &_port, PacketPtr _pkt,
        bool needResp_)
    : ReqCompl(_pkt), port(_port), needResp(needResp_), keep(false)
{
}

void
TimingReqCompl::setDone()
{
    done = true;
    port.timingReqCompl(*this);
    if (!keep)
        delete this;
}

} // namespace Pci
} // namespace Simbricks
} // namespace gem5
