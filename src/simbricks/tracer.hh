/*
 * Copyright 2026 SimBricks UG (haftungsbeschränkt)
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

#ifndef __SIMBRICKS_TRACER_HH__
#define __SIMBRICKS_TRACER_HH__

/*
 * Instruction tracer that logs the CPU/software events simbricks-trace
 * consumes (debug flag SimBricksCpu, lines "simbricks-cpu: ..."):
 *
 *  - syscall / sysret / iret macroops, logged when their last microop
 *    commits (the CPU models only dump trace records for committed
 *    instructions, so nothing speculative is logged);
 *  - kernel PC hooks: configured symbols at which a line with selected
 *    registers is printed, optionally with a one-shot hook at the return
 *    address of that call.
 *
 * Attached as `cpu.tracer`; one instance per CPU.
 */

#include <set>
#include <string>
#include <vector>

#include "base/types.hh"
#include "cpu/pc_event.hh"
#include "cpu/static_inst.hh"
#include "cpu/thread_context.hh"
#include "params/SimBricksTracer.hh"
#include "sim/eventq.hh"
#include "sim/insttracer.hh"

namespace gem5 {

class System;
namespace loader { class SymbolTable; }

namespace simbricks {

class Tracer;

/* One configured hook: `symbol[:reg,reg,...][:ret]`. */
struct HookSpec
{
    std::string symbol;
    std::vector<RegId> regs;
    bool ret;
};

/* Entry hook at a configured PC. */
class HookEvent : public PCEvent
{
  public:
    HookEvent(PCEventScope *scope, Tracer &tracer, unsigned id, Addr pc);
    void process(ThreadContext *tc) override;

  private:
    Tracer &tracer;
    unsigned id;
};

/* One-shot hook at the return address of a hooked call. Fires only for the
 * thread context and stack pointer of that call. */
class RetHookEvent : public PCEvent
{
  public:
    RetHookEvent(PCEventScope *scope, Tracer &tracer, unsigned id, Addr pc,
                 ContextID ctx, Addr sp);
    void process(ThreadContext *tc) override;

  private:
    Tracer &tracer;
    unsigned id;
    ContextID ctx;
    Addr sp;
    bool done;
};

class TracerRecord : public trace::InstRecord
{
  public:
    enum Kind { SYSCALL, SYSRET, IRET };

    TracerRecord(Tick when, ThreadContext *tc, const StaticInstPtr inst,
                 const PCStateBase &pc, const StaticInstPtr macro,
                 Kind kind, const Tracer &tracer)
        : InstRecord(when, tc, inst, pc, macro), kind(kind), tracer(tracer)
    {}

    void dump() override;

  private:
    Kind kind;
    const Tracer &tracer;
};

class Tracer : public trace::InstTracer
{
  public:
    PARAMS(SimBricksTracer);
    Tracer(const Params &p);

    void startup() override;

    trace::InstRecord *
    getInstRecord(Tick when, ThreadContext *tc, const StaticInstPtr inst,
                  const PCStateBase &pc,
                  const StaticInstPtr macro = nullptr) override;

    /* Called by the hook events. */
    void hookHit(unsigned id, ThreadContext *tc);
    void retHookHit(unsigned id, ThreadContext *tc, Addr pc);
    void retire(PCEvent *event);

    /* Written into gem5's output directory at startup when tracing is on. */
    static const char *const SYMBOLS_FILE;

  private:
    void parseHook(const std::string &spec);
    void dumpSymbols(const loader::SymbolTable &symtab);
    void sweep();

    System *system;
    std::vector<HookSpec> hooks;
    std::vector<PCEvent *> garbage;
    EventFunctionWrapper sweepEvent;

    /* Systems whose hooks are installed: every CPU carries a tracer with
     * the same hook list, but the hooks must be scheduled only once. */
    static std::set<System *> installed;
};

} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_TRACER_HH__
