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

#ifndef __SIMBRICKS_BASE_HH__
#define __SIMBRICKS_BASE_HH__

#include "base/callback.hh"
#include "sim/eventq.hh"
#include "sim/sim_object.hh"

namespace gem5 {
namespace simbricks {
extern "C" {
#include <simbricks/base/if.h>

};

namespace base {

class InitManager;
class Adapter : public EventManager
{
  private:
    friend class InitManager;

    bool sync;
    bool isListen;
    Tick pollInterval;
    EventFunctionWrapper inEvent;
    EventFunctionWrapper outSyncEvent;
    struct SimbricksBaseIf baseIf;
    struct SimbricksBaseIfSHMPool *pool;
    struct SimbricksBaseIfParams params;

    void processInEvent();
    void processOutSyncEvent();

    void commonInit(const std::string &sock_path);
  protected:
    void close();
    virtual size_t introOutPrepare(void *data, size_t maxlen);
    virtual void introInReceived(const void *data, size_t len);
    virtual void handleInMsg(volatile union SimbricksProtoBaseMsg *msg);
    virtual void initIfParams(SimbricksBaseIfParams &p);

  public:
    Adapter(SimObject &parent, bool sync_);
    virtual ~Adapter();

    void cfgSetPollInterval(Tick i) {
        pollInterval = i;
    }

    void connect(const std::string &sock_path);
    void listen(const std::string &sock_path, const std::string &shm_path);
    void init();
    void startup();

    bool poll();

    void inDone(volatile union SimbricksProtoBaseMsg *msg) {
        SimbricksBaseIfInDone(&baseIf, msg);
    }

    uint8_t inType(volatile union SimbricksProtoBaseMsg *msg) {
        return SimbricksBaseIfInType(&baseIf, msg);
    }

    volatile union SimbricksProtoBaseMsg *outAlloc() {
        volatile union SimbricksProtoBaseMsg *msg;
        do {
            msg = SimbricksBaseIfOutAlloc(&baseIf, curTick());
        } while (!msg);
        return msg;
    }

    void outSend(volatile union SimbricksProtoBaseMsg *msg, uint8_t ty) {
        SimbricksBaseIfOutSend(&baseIf, msg, ty);
    }
};

template <typename TMI, typename TMO>
class GenericBaseAdapter : public Adapter
{
  public:
    class Interface
    {
      public:
        virtual size_t introOutPrepare(void *data, size_t maxlen) = 0;
        virtual void introInReceived(const void *data, size_t len) = 0;
        virtual void handleInMsg(volatile TMI *msg) = 0;
        virtual void initIfParams(SimbricksBaseIfParams &p) = 0;
    };

  protected:
    Interface &intf;

    virtual size_t introOutPrepare(void *data, size_t len) {
        return intf.introOutPrepare(data, len);
    }

    virtual void introInReceived(const void *data, size_t len) {
        intf.introInReceived(data, len);
    }

    virtual void handleInMsg(volatile union SimbricksProtoBaseMsg *msg) {
        intf.handleInMsg((volatile TMI *) msg);
    }

    virtual void initIfParams(SimbricksBaseIfParams &p) {
        Adapter::initIfParams(p);
        intf.initIfParams(p);
    }

  public:
    GenericBaseAdapter(SimObject &parent, Interface &intf_, bool sync_)
      : Adapter(parent, sync_), intf(intf_) {}

    virtual ~GenericBaseAdapter() = default;

    void inDone(volatile TMI *msg) {
        Adapter::inDone((volatile union SimbricksProtoBaseMsg *) msg);
    }

    uint8_t inType(volatile TMI *msg) {
        return Adapter::inType((volatile union SimbricksProtoBaseMsg *) msg);
    }

    volatile TMO *outAlloc() {
        return (volatile TMO *) Adapter::outAlloc();
    }

    void outSend(volatile TMO *msg, uint8_t ty) {
        Adapter::outSend((volatile union SimbricksProtoBaseMsg *) msg, ty);
    }
};

} // namespace base
} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_BASE_HH__
