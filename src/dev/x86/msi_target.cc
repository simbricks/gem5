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
#include "mem/packet.hh"
#include "mem/packet_access.hh"
#include "sim/system.hh"
#include "debug/MSITarget.hh"

X86ISA::MSITarget::MSITarget(Params *p)
    : BasicPioDevice(p, 0x1000000),
      intMasterPort(name() + ".int_master", this, this, p->int_latency)
{
}

void
X86ISA::MSITarget::init()
{
    // The io apic must register its address range with its pio port via
    // the piodevice init() function.
    BasicPioDevice::init();

    // If the master port isn't connected, we can't send interrupts anywhere.
    panic_if(!intMasterPort.isConnected(),
            "Int port not connected to anything!");
}

Port &
X86ISA::MSITarget::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "int_master")
        return intMasterPort;
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
    DPRINTF(MSITarget, "Received write addr=%x val=%x.\n", pkt->getAddr(),
            pkt->getLE<uint32_t>());
    uint8_t d_apic = (pkt->getAddr() >> 12) & 0xff;
    uint32_t d_data = pkt->getLE<uint32_t>();

    TriggerIntMessage message = 0;
    message.destination = d_apic;
    message.vector = d_data & 0xff;
    message.deliveryMode = DeliveryMode::ExtInt;

    PacketPtr intPkt = buildIntTriggerPacket(d_apic, message);
    intMasterPort.sendMessage(intPkt, sys->isTimingMode());

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

X86ISA::MSITarget *
MSITargetParams::create()
{
    return new X86ISA::MSITarget(this);
}
