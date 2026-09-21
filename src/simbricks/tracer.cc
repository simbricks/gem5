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

#include "simbricks/tracer.hh"

#include <map>
#include <sstream>

#include "arch/x86/regs/int.hh"
#include "arch/x86/regs/misc.hh"
#include "base/cprintf.hh"
#include "base/loader/symtab.hh"
#include "base/logging.hh"
#include "base/output.hh"
#include "base/trace.hh"
#include "debug/SimBricksCpu.hh"
#include "mem/translating_port_proxy.hh"
#include "sim/cur_tick.hh"
#include "sim/pseudo_inst.hh"
#include "sim/system.hh"

namespace gem5 {
namespace simbricks {

namespace {

const std::map<std::string, RegId> regNames = {
    {"rax", X86ISA::int_reg::Rax}, {"rbx", X86ISA::int_reg::Rbx},
    {"rcx", X86ISA::int_reg::Rcx}, {"rdx", X86ISA::int_reg::Rdx},
    {"rsi", X86ISA::int_reg::Rsi}, {"rdi", X86ISA::int_reg::Rdi},
    {"rbp", X86ISA::int_reg::Rbp}, {"rsp", X86ISA::int_reg::Rsp},
    {"r8", X86ISA::int_reg::R8},   {"r9", X86ISA::int_reg::R9},
    {"r10", X86ISA::int_reg::R10}, {"r11", X86ISA::int_reg::R11},
    {"r12", X86ISA::int_reg::R12}, {"r13", X86ISA::int_reg::R13},
    {"r14", X86ISA::int_reg::R14}, {"r15", X86ISA::int_reg::R15},
};

std::vector<std::string>
split(const std::string &s, char sep)
{
    std::vector<std::string> out;
    std::stringstream ss(s);
    std::string part;
    while (std::getline(ss, part, sep))
        out.push_back(part);
    return out;
}

/* All lines go through here so they share the name and flag. */
template <typename ...Args>
void
line(const Tracer &tracer, const char *fmt, const Args &...args)
{
    trace::getDebugLogger()->dprintf_flag(curTick(), tracer.name(),
                                          "SimBricksCpu", fmt, args...);
}

int
cpl(ThreadContext *tc)
{
    X86ISA::HandyM5Reg m5reg =
        tc->readMiscRegNoEffect(X86ISA::misc_reg::M5Reg);
    return m5reg.cpl;
}

} // anonymous namespace

// -------
// Hooks  -
// -------

HookEvent::HookEvent(PCEventScope *scope, Tracer &tracer, unsigned id,
                     Addr pc)
    : PCEvent(scope, "simbricks-hook", pc), tracer(tracer), id(id)
{
}

void
HookEvent::process(ThreadContext *tc)
{
    tracer.hookHit(id, tc);
}

RetHookEvent::RetHookEvent(PCEventScope *scope, Tracer &tracer, unsigned id,
                           Addr pc, ContextID ctx, Addr sp)
    : PCEvent(scope, "simbricks-hookret", pc), tracer(tracer), id(id),
      ctx(ctx), sp(sp), done(false)
{
}

void
RetHookEvent::process(ThreadContext *tc)
{
    // Keyed by the stack pointer alone: kernel stacks are per task, and a
    // task that blocked in the hooked function may return on another CPU.
    if (done || tc->getReg(X86ISA::int_reg::Rsp) != sp)
        return;
    done = true;
    tracer.retHookHit(id, tc, pc());
    tracer.retire(this);
}

// ---------------------
// syscall/sysret/iret  -
// ---------------------

void
TracerRecord::dump()
{
    using namespace X86ISA;
    ThreadContext *tc = thread;
    int cpu = tc->contextId();
    switch (kind) {
      case SYSCALL:
        // sp is the user stack pointer, which the thread has again when
        // the syscall returns: together with cr3 it identifies the thread.
        line(tracer, "simbricks-cpu: syscall cpu %d nr %d a0 %#x a1 %#x "
             "a2 %#x pc %#x sp %#x\n", cpu, tc->getReg(int_reg::Rax),
             tc->getReg(int_reg::Rdi), tc->getReg(int_reg::Rsi),
             tc->getReg(int_reg::Rdx), pc->instAddr(),
             tc->getReg(int_reg::Rsp));
        break;
      case SYSRET:
        // rcx holds the user return address
        line(tracer, "simbricks-cpu: sysret cpu %d ret %#x pc %#x sp %#x\n",
             cpu, tc->getReg(int_reg::Rax), tc->getReg(int_reg::Rcx),
             tc->getReg(int_reg::Rsp));
        break;
      case IRET:
        line(tracer, "simbricks-cpu: iret cpu %d cpl %d sp %#x\n", cpu,
             cpl(tc), tc->getReg(int_reg::Rsp));
        break;
    }
}

// --------
// Tracer  -
// --------

std::set<System *> Tracer::installed;
const char *const Tracer::SYMBOLS_FILE = "simbricks-symbols.txt";

Tracer::Tracer(const Params &p)
    : trace::InstTracer(p), system(p.system),
      sweepEvent([this]{ sweep(); }, name())
{
    for (const std::string &spec : p.hooks)
        parseHook(spec);
}

void
Tracer::parseHook(const std::string &spec)
{
    std::vector<std::string> parts = split(spec, ':');
    if (parts.empty() || parts[0].empty())
        fatal("%s: empty hook spec '%s'", name(), spec);
    HookSpec hook;
    hook.symbol = parts[0];
    hook.ret = false;
    for (size_t i = 1; i < parts.size(); i++) {
        if (parts[i] == "ret") {
            hook.ret = true;
            continue;
        }
        for (const std::string &reg : split(parts[i], ',')) {
            auto it = regNames.find(reg);
            if (it == regNames.end())
                fatal("%s: unknown register '%s' in hook '%s'", name(), reg,
                      spec);
            hook.regs.push_back(it->second);
        }
    }
    hooks.push_back(hook);
}

void
Tracer::dumpSymbols(const loader::SymbolTable &symtab)
{
    // The kernel symbols as gem5 loaded them, for the collector to ship and
    // the aggregator to resolve PCs with: "<addr> <size> <t> <name>" per
    // line, t = F(unction) / O(bject) / N(other); size 0 when unknown.
    OutputStream *out = simout.create(SYMBOLS_FILE, false, true);
    std::ostream &os = *out->stream();
    for (const loader::Symbol &sym : symtab) {
        char t = 'N';
        if (sym.type() == loader::Symbol::SymbolType::Function)
            t = 'F';
        else if (sym.type() == loader::Symbol::SymbolType::Object)
            t = 'O';
        ccprintf(os, "%#x %d %c %s\n", sym.address(), sym.sizeOrDefault(0), t,
                 sym.name());
    }
    simout.close(out);
}

void
Tracer::startup()
{
    trace::InstTracer::startup();
    if (!debug::SimBricksCpu || installed.count(system))
        return;
    installed.insert(system);
    panic_if(system->threads.size() == 0, "%s: no thread contexts", name());
    ThreadContext *tc = system->threads[0];
    const loader::SymbolTable &symtab = system->workload->symtab(tc);
    dumpSymbols(symtab);
    // Hooks are scheduled through the system so they reach every thread
    // context, including ones swapped in later (checkpoint restore, CPU
    // switch).
    for (unsigned id = 0; id < hooks.size(); id++) {
        const HookSpec &hook = hooks[id];
        Addr pc;
        if (hook.symbol.rfind("0x", 0) == 0) {
            pc = std::stoull(hook.symbol, nullptr, 16);
        } else {
            auto sym = symtab.find(hook.symbol);
            if (sym == symtab.end()) {
                warn("%s: hook symbol '%s' not found", name(), hook.symbol);
                continue;
            }
            pc = sym->address();
        }
        new HookEvent(system, *this, id, pc);  // schedules itself
        DPRINTF(SimBricksCpu, "simbricks-cpu: hookdef id %d pc %#x ret %d "
                "name %s\n", id, pc, hook.ret ? 1 : 0, hook.symbol);
    }
}

trace::InstRecord *
Tracer::getInstRecord(Tick when, ThreadContext *tc, const StaticInstPtr inst,
                      const PCStateBase &pc, const StaticInstPtr macro)
{
    if (!debug::SimBricksCpu || !macro || !inst->isLastMicroop())
        return nullptr;
    // x86 macroop mnemonics are the definition name up to the first
    // underscore: SYSCALL_64 and SYSCALL_COMPAT both read "syscall".
    const std::string m = macro->getName();
    TracerRecord::Kind kind;
    if (m == "syscall")
        kind = TracerRecord::SYSCALL;
    else if (m == "sysret")
        kind = TracerRecord::SYSRET;
    else if (m == "iret")
        kind = TracerRecord::IRET;
    else
        return nullptr;
    return new TracerRecord(when, tc, inst, pc, macro, kind, *this);
}

void
Tracer::hookHit(unsigned id, ThreadContext *tc)
{
    if (!debug::SimBricksCpu)
        return;
    const HookSpec &hook = hooks[id];
    Addr sp = tc->getReg(X86ISA::int_reg::Rsp);
    std::string regs;
    for (size_t i = 0; i < hook.regs.size(); i++)
        regs += csprintf(" r%d %#x", i, tc->getReg(hook.regs[i]));
    line(*this, "simbricks-cpu: hook id %d cpu %d pc %#x sp %#x%s\n", id,
         tc->contextId(), tc->pcState().instAddr(), sp, regs);
    if (!hook.ret)
        return;
    uint64_t ret;
    TranslatingPortProxy proxy(tc);
    if (!proxy.tryReadBlob(sp, &ret, sizeof(ret))) {
        warn_once("%s: cannot read return address for hook %s", name(),
                  hook.symbol);
        return;
    }
    // Fires when the callee returns: stack pointer popped. A CPU that re-fetches
    // the hooked instruction (icache miss) services the PC event again; one
    // return hook per pending call is enough.
    if (!pendingRets.insert(std::make_pair(ret, sp + 8)).second)
        return;
    new RetHookEvent(system, *this, id, ret, tc->contextId(), sp + 8);
}

void
Tracer::retHookHit(unsigned id, ThreadContext *tc, Addr pc)
{
    if (!debug::SimBricksCpu)
        return;
    // sp is the entry stack pointer + 8, which pairs the return with its call
    line(*this, "simbricks-cpu: hookret id %d cpu %d pc %#x ret %#x sp %#x\n",
         id, tc->contextId(), pc, tc->getReg(X86ISA::int_reg::Rax),
         tc->getReg(X86ISA::int_reg::Rsp));
    pendingRets.erase(std::make_pair(pc, (Addr)tc->getReg(X86ISA::int_reg::Rsp)));
}

void
Tracer::retire(PCEvent *event)
{
    // The queue is being iterated while the event runs; remove it later.
    garbage.push_back(event);
    if (!sweepEvent.scheduled())
        schedule(sweepEvent, curTick());
}

void
Tracer::sweep()
{
    for (PCEvent *ev : garbage)
        delete ev;  // removes itself from the scope
    garbage.clear();
}

uint64_t
pageTableBase(ThreadContext *tc)
{
    return tc->readMiscRegNoEffect(X86ISA::misc_reg::Cr3);
}

} // namespace simbricks
} // namespace gem5
