/*
 * Copyright 2024 Max Planck Institute for Software Systems, and
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

#ifndef __SIMBRICKS_CUR_TICK_HH__
#define __SIMBRICKS_CUR_TICK_HH__

#include "sim/cur_tick.hh"

/**
 * For SimBricks messages, we want the simulation to look like it started at
 * tick 0. The reason is that otherwise, after restoring a checkpoint, connected
 * simulators first have to catch up, i.e. simulate until the checkpoint tick
 * before the simulation can continue.
 */

namespace gem5 {
namespace simbricks {
namespace base {
void setStartTick();
Tick getStartTick();

inline uint64_t toSimbricksTs(Tick gem5_tick) {
  return gem5_tick - getStartTick();
}
inline Tick fromSimbricksTs(uint64_t simbricks_ts) {
  return simbricks_ts + getStartTick();
}
inline uint64_t curTickAsSimbricksTs() {
  return toSimbricksTs(gem5::curTick());
}
}  // namespace base
}  // namespace simbricks
}  // namespace gem5

#endif