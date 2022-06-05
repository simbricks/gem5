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

#ifndef __SIMBRICKS_ETHERNET_HH__
#define __SIMBRICKS_ETHERNET_HH__

#include <queue>

#include "params/SimBricksEthernet.hh"
#include "dev/net/etherint.hh"
#include "simbricks/base.hh"

namespace simbricks {
namespace ethernet {
extern "C" {
#include <simbricks/network/proto.h>
}

class Adapter :
    public SimObject,
    public base::GenericBaseAdapter <SimbricksProtoNetMsg,
                                     SimbricksProtoNetMsg>::Interface
{
protected:
    // SimBricks base adapter
    base::GenericBaseAdapter
        <SimbricksProtoNetMsg, SimbricksProtoNetMsg> adapter;
    bool sync;

    virtual size_t introOutPrepare(void *data, size_t maxlen) override;
    virtual void introInReceived(const void *data, size_t len) override;
    virtual void initIfParams(SimbricksBaseIfParams &p) override;
    virtual void handleInMsg(volatile SimbricksProtoNetMsg *msg) override;

    bool recvPacket(EthPacketPtr packet);

    class Interface : public EtherInt {
      private:
        Adapter *adapter;
      public:
        Interface(const std::string &name, Adapter *a) :
            EtherInt(name), adapter(a) { }

        bool recvPacket(EthPacketPtr pkt) override {
            return adapter->recvPacket(pkt);
        }

        void sendDone() override {}
    };

    Interface *interface;

public:
    typedef SimBricksEthernetParams Params;
    const Params *params() const {
        return dynamic_cast<const Params *>(_params);
    }

    Adapter(const Params *p);
    virtual ~Adapter();

    virtual Port &getPort(const std::string &if_name,
                          PortID idx=InvalidPortID) override;

    void init() override;
    virtual void startup() override;
};

} // namespace ethernet
} // namespace simbricks

#endif // __SIMBRICKS_ETHERNET_HH__