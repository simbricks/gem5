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

#ifndef __SIMBRICKS_INIT_MANAGER_HH__
#define __SIMBRICKS_INIT_MANAGER_HH__

#include <set>

#include "simbricks/base.hh"

namespace gem5 {
namespace simbricks {
namespace base {

/**
 * A challenge with SimBricks adapter initialization is that it conceptually
 * requires multiple adapters to be initialized asynchronously to avoid any
 * deadlocks. Each adapter has to wait for a ux socket connection to be
 * accepted or an outgoing connection established, then send and wait for the
 * received intro message.
 * To avoid deadlocks in the full simbricks simulation, we use non-blocking I/O
 * and do initialization in two phases. First create all adapters and register
 * them with the init manager. Then in the "startup phase" after all adapters
 * are registered, we can then process I/O events across all of them and wait
 * for initialization to complete, while also completing other I/O events as
 * needed.
 */
class InitManager
{
    protected:
        std::set <Adapter *> unconnected;
        std::set <Adapter *> waitRx;

        InitManager();

        void processEvents();
        void connected(Adapter &a);
    public:
        static InitManager &get();

        void registerAdapter(Adapter &a);
        void waitReady(Adapter &a);
};

} // namespace base
} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_INIT_MANAGER_HH__
