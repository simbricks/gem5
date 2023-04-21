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

#include <debug/SimBricksEthernet.hh>
#include <simbricks/ethernet.hh>

#include "base/trace.hh"

namespace gem5 {
namespace simbricks {
namespace ethernet {

extern "C" {
#include <simbricks/network/if.h>

}

Adapter::Adapter(const Params &p)
    : SimObject(p),
    base::GenericBaseAdapter<SimbricksProtoNetMsg, SimbricksProtoNetMsg>::
        Interface(*this),
    adapter(*this, *this, p.sync),
    sync(p.sync)
{
    DPRINTF(SimBricksEthernet, "device constructed\n");

    interface = new Interface(name() + ".int0", this);

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
    size_t introlen = sizeof(struct SimbricksProtoNetIntro);
    assert(introlen <= maxlen);
    memset(data, 0, introlen);
    return introlen;
}

void
Adapter::introInReceived(const void *data, size_t len)
{
    assert(len == sizeof(struct SimbricksProtoNetIntro));
}

void
Adapter::initIfParams(SimbricksBaseIfParams &p)
{
    SimbricksNetIfDefaultParams(&p);
    p.link_latency = params().link_latency;
    p.sync_interval = params().sync_tx_interval;
}

Port &
Adapter::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "int0") {
        return *interface;
    }
    return SimObject::getPort(if_name, idx);
}

void
Adapter::init()
{
    /* not calling parent init on purpose, as that will cause problems because
     * PIO port is not connected */
    if (!interface->isConnected())
        panic("int0 interface of %s not connected!", name());

    adapter.init();
}

void
Adapter::handleInMsg(volatile union SimbricksProtoNetMsg *msg)
{
    volatile struct SimbricksProtoNetMsgPacket *pkt = &msg->packet;

    uint8_t ty = adapter.inType(msg);
    if (ty != SIMBRICKS_PROTO_NET_MSG_PACKET) {
        panic("simbricks::ethernet: unsupported msg type=%x", ty);
    }

    unsigned len = pkt->len;
    EthPacketPtr packet = std::make_shared<EthPacketData>(len);
    packet->length = len;
    packet->simLength = len;
    memcpy(packet->data, (const void *) pkt->data, len);

    DPRINTF(SimBricksEthernet, "real->sim len=%d\n", len);
    interface->sendPacket(packet);
    adapter.inDone(msg);
}

bool
Adapter::recvPacket(EthPacketPtr packet)
{
    DPRINTF(SimBricksEthernet, "sending out a packet\n");
    volatile union SimbricksProtoNetMsg *msg_to = adapter.outAlloc();

    volatile struct SimbricksProtoNetMsgPacket *pkt_to = &msg_to->packet;
    pkt_to->len = packet->length;
    pkt_to->port = 0;
    memcpy((void *)pkt_to->data, packet->data, packet->length);

    adapter.outSend(msg_to, SIMBRICKS_PROTO_NET_MSG_PACKET);
    interface->recvDone();
    return true;
}

void
Adapter::startup()
{
    adapter.startup();
}

} // namespace ethernet
} // namespace simbricks
} // namespace gem5
