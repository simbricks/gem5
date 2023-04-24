/*
 * Copyright (c) 2008 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "dev/x86/msi_target.hh"

#include <list>

#include "arch/x86/interrupts.hh"
#include "arch/x86/intmessage.hh"
#include "cpu/base.hh"
#include "debug/MSITarget.hh"
#include "mem/packet.hh"
#include "mem/packet_access.hh"
#include "sim/system.hh"

namespace gem5
{

X86ISA::MSITarget::MSITarget(const Params &p)
    : BasicPioDevice(p, 0x1000000),
      intRequestPort(name() + ".int_requestor", this, this, p.int_latency)
{
}

void
X86ISA::MSITarget::init()
{
    // The io apic must register its address range with its pio port via
    // the piodevice init() function.
    BasicPioDevice::init();

    // If the requestor port isn't connected, we can't send interrupts
    // anywhere.
    panic_if(!intRequestPort.isConnected(),
            "Int port not connected to anything!");
}

Port &
X86ISA::MSITarget::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "int_requestor")
        return intRequestPort;
    else
        return BasicPioDevice::getPort(if_name, idx);
}

Tick
X86ISA::MSITarget::read(PacketPtr pkt)
{
    panic("Illegal read from MSI Target.\n");
    return pioDelay;
}

Tick
X86ISA::MSITarget::write(PacketPtr pkt)
{
    uint64_t d_addr = pkt->getAddr();
    uint16_t d_data = pkt->getLE<uint16_t>();

    DPRINTF(MSITarget, "Received write addr=%x val=%x.\n", d_addr, d_data);

    TriggerIntMessage message = 0;
    message.destination = (d_addr >> 12) & 0xff;;
    message.vector = d_data & 0xff;
    message.deliveryMode = d_data >> 8 & 0x7;
    message.destMode = (d_addr >> 2) & 1;
    message.level = (d_data >> 14) & 1;
    message.trigger = (d_data >> 14) & 1;

    DPRINTF(MSITarget, "Received write addr=%x val=%x dest=%x vec=%x\n",
        d_addr, d_data, message.destination, message.vector);

    std::list<int> apics;
    int numContexts = sys->threads.size();
    if (message.destMode == 0) {
        /* physical destination mode */
        if (message.deliveryMode == delivery_mode::LowestPriority) {
            panic("Lowest priority delivery mode from the "
                    "IO APIC aren't supported in physical "
                    "destination mode.\n");
        }
        if (message.destination == 0xFF) {
            for (int i = 0; i < numContexts; i++) {
                apics.push_back(i);
            }
        } else {
            apics.push_back(message.destination);
        }
    } else {
        for (int i = 0; i < numContexts; i++) {
            BaseInterrupts *base_int = sys->threads[i]->getCpuPtr()->
                getInterruptController(0);
            auto *localApic = dynamic_cast<Interrupts *>(base_int);
            if ((localApic->readReg(APIC_LOGICAL_DESTINATION) >> 24) &
                    message.destination) {
                apics.push_back(localApic->getInitialApicId());
            }
        }
        if (message.deliveryMode == delivery_mode::LowestPriority &&
                apics.size()) {
            // The manual seems to suggest that the chipset just does
            // something reasonable for these instead of actually using
            // state from the local APIC. We'll just rotate an offset
            // through the set of APICs selected above.
            uint64_t modOffset = lowestPriorityOffset % apics.size();
            lowestPriorityOffset++;
            auto apicIt = apics.begin();
            while (modOffset--) {
                apicIt++;
                assert(apicIt != apics.end());
            }
            int selected = *apicIt;
            apics.clear();
            apics.push_back(selected);
        }
    }
    for (auto id: apics) {
        PacketPtr pkt = buildIntTriggerPacket(id, message);
        intRequestPort.sendMessage(pkt, sys->isTimingMode());
    }

    pkt->makeAtomicResponse();
    return pioDelay;
}

void
X86ISA::MSITarget::serialize(CheckpointOut &cp) const
{
    BasicPioDevice::serialize(cp);
}

void
X86ISA::MSITarget::unserialize(CheckpointIn &cp)
{
    BasicPioDevice::unserialize(cp);
}

} // namespace gem5
