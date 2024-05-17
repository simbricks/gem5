#include "simbricks/cur_tick.hh"

#include "base/types.hh"

namespace gem5 {
namespace simbricks {
namespace base {
gem5::Tick StartTick = 0;

void setStartTick() {
  StartTick = curTick();
}

Tick getStartTick() {
  return StartTick;
}
}  // namespace base
}  // namespace simbricks
}  // namespace gem5