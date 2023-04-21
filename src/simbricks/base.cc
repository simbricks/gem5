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

#include "simbricks/base.hh"

#include "base/trace.hh"
#include "debug/SimBricks.hh"
#include "debug/SimBricksSync.hh"
#include "sim/core.hh"
#include "simbricks/init_manager.hh"

namespace gem5 {
namespace simbricks {
namespace base {

Adapter::Adapter(SimObject &parent, bool sync_)
    : EventManager(parent),
      sync(sync_), isListen(false), pollInterval(500000),
      inEvent([this]{ processInEvent(); }, name() + "SimBricksIn", false, 10),
      outSyncEvent([this]{ processOutSyncEvent(); }, name() + "SimBricksSync",
                   false, 0),
      pool(nullptr)
{
}

Adapter::~Adapter()
{
}

void
Adapter::close()
{
    SimbricksBaseIfClose(&baseIf);
    if (isListen)
        SimbricksBaseIfUnlink(&baseIf);

    if (pool) {
        SimbricksBaseIfSHMPoolUnlink(pool);
        SimbricksBaseIfSHMPoolUnmap(pool);
    }
}

void
Adapter::processInEvent()
{
    DPRINTF(SimBricks, "simbricks: processInEvent\n");

    /* run what we can */
    while (poll());

    if (sync) {
        /* in sychronized mode we might need to wait till we get a message with
         * a timestamp allowing us to proceed */
        Tick nextTs;
        while ((nextTs = SimbricksBaseIfInTimestamp(&baseIf)) <= curTick()) {
            poll();
        }

        schedule(inEvent, nextTs);
    } else {
        /* in non-synchronized mode just poll at fixed intervals */
        schedule(inEvent, curTick() + pollInterval);
    }
}

void
Adapter::processOutSyncEvent()
{
    DPRINTF(SimBricks, "simbricks: sending sync message\n");
    while (SimbricksBaseIfOutSync(&baseIf, curTick()));
    schedule(outSyncEvent, SimbricksBaseIfOutNextSync(&baseIf));
}

void
Adapter::commonInit(const std::string &sock_path)
{
    SimbricksBaseIfDefaultParams(&params);
    initIfParams(params);

    params.sock_path = sock_path.c_str();
    params.blocking_conn = false;
    if (sync)
        params.sync_mode = kSimbricksBaseIfSyncRequired;
    else
        params.sync_mode = kSimbricksBaseIfSyncDisabled;

    if (SimbricksBaseIfInit(&baseIf, &params))
        panic("base init failed");

    registerExitCallback([this]() { close(); });
}

size_t
Adapter::introOutPrepare(void *data, size_t maxlen)
{
    return 0;
}

void
Adapter::introInReceived(const void *data, size_t len)
{
}

void
Adapter::handleInMsg(volatile union SimbricksProtoBaseMsg *msg)
{
    DPRINTF(SimBricks, "simbricks: ignoring unhandled incoming message\n");
    // by default just ignore messages but mark them as done
    inDone(msg);
}

void
Adapter::initIfParams(SimbricksBaseIfParams &p)
{
}


void
Adapter::connect(const std::string &sock_path)
{
    DPRINTF(SimBricks, "simbricks: initiating outgoing connection\n");

    commonInit(sock_path);

    if (SimbricksBaseIfConnect(&baseIf))
        panic("connecting failed");

    // register this adapter for the rest of the initialization
    // see init_manager.hh for rationale
    InitManager::get().registerAdapter(*this);
}

void
Adapter::listen(const std::string &sock_path, const std::string &shm_path)
{
    DPRINTF(SimBricks, "simbricks: listening for incomping connection\n");
    commonInit(sock_path);

    pool = new SimbricksBaseIfSHMPool;
    if (SimbricksBaseIfSHMPoolCreate(pool, shm_path.c_str(),
            SimbricksBaseIfSHMSize(&params)))
        panic("creating SHM pool failed");

    if (SimbricksBaseIfListen(&baseIf, pool))
        panic("listening failed");

    isListen = true;

    // register this adapter for the rest of the initialization
    // see init_manager.hh for rationale
    InitManager::get().registerAdapter(*this);
}

void
Adapter::init()
{
    // wait for initialization of this adapter to be complete
    InitManager::get().waitReady(*this);
}

void
Adapter::startup()
{
    // schedule first sync to be sent immediately
    if (sync)
        schedule(outSyncEvent, curTick());
    // next schedule
    schedule(inEvent, curTick() + 1);
}

bool
Adapter::poll()
{
    volatile union SimbricksProtoBaseMsg *msg =
        SimbricksBaseIfInPoll(&baseIf, curTick());
    if (!msg)
        return false;

    // don't pass sync messages to handle msg function
    if (SimbricksBaseIfInType(&baseIf, msg) == SIMBRICKS_PROTO_MSG_TYPE_SYNC) {
        inDone(msg);
        return true;
    }

    handleInMsg(msg);
    return true;
}

} // namespace base
} // namespace simbricks
} // namespace gem5
