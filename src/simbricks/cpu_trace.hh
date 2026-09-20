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

#ifndef __SIMBRICKS_CPU_TRACE_HH__
#define __SIMBRICKS_CPU_TRACE_HH__

/*
 * Helpers for the software-attribution fields the SimBricks adapters print
 * in their debug output: which CPU (thread context) issued a request and at
 * which PC, and which APIC vector an MSI message carries. The debug lines
 * are consumed by the simbricks-trace collector.
 */

#include <cstdint>

#include "mem/packet.hh"
#include "mem/request.hh"

namespace gem5 {
namespace simbricks {

/* Context id of the request's issuer, -1 when the request has none (DMA,
 * KVM, functional accesses). */
inline int
reqContextId(const PacketPtr pkt)
{
    if (!pkt->req || !pkt->req->hasContextId())
        return -1;
    return pkt->req->contextId();
}

/* PC of the instruction that issued the request, 0 when unknown. */
inline Addr
reqPC(const PacketPtr pkt)
{
    if (!pkt->req || !pkt->req->hasPC())
        return 0;
    return pkt->req->getPC();
}

/* Vector the local APIC will see for an MSI message: the low byte of the
 * message data (the adapter sends the capability's data word unmodified,
 * so this is what gets delivered even for multi-message MSI). */
inline unsigned
msiApicVector(uint16_t msg_data)
{
    return msg_data & 0xff;
}

/* Destination APIC id in the low dword of an MSI address. */
inline unsigned
msiApicDest(uint32_t addr_lo)
{
    return (addr_lo >> 12) & 0xff;
}

} // namespace simbricks
} // namespace gem5

#endif // __SIMBRICKS_CPU_TRACE_HH__
