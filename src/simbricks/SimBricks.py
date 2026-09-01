# Copyright (c) 2022 Max Planck Institute for Software Systems, and
# National University of Singapore
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met: redistributions of source code must retain the above copyright
# notice, this list of conditions and the following disclaimer;
# redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution;
# neither the name of the copyright holders nor the names of its
# contributors may be used to endorse or promote products derived from
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from m5.defines import buildEnv
from m5.SimObject import SimObject
from m5.params import *
from m5.proxy import *
from m5.objects.Device import BadAddr
from m5.objects.Ethernet import EtherInt
from m5.objects.PciDevice import PciBar
from m5.objects.PciDevice import PciEndpoint
from m5.objects.PciHost import PciHost


class SimBricksEthernet(SimObject):
    type = "SimBricksEthernet"
    cxx_class = "gem5::simbricks::ethernet::Adapter"
    cxx_header = "simbricks/ethernet.hh"

    int0 = EtherInt("interface 0")

    listen = Param.Bool(False, "Open listening instead of connecting")
    uxsocket_path = Param.String("unix socket path")
    shm_path = Param.String("Shared memory path")
    sync = Param.Bool(False, "Synchronize over Ethernet")
    poll_interval = Param.Latency("100us", "poll interval size (unsync only)")
    sync_tx_interval = Param.Latency("500ns", "interval between syncs")
    link_latency = Param.Latency("500ns", "Ethernet latency")


class SimBricksMem(SimObject):
    type = "SimBricksMem"
    cxx_class = "gem5::simbricks::mem::Adapter"
    cxx_header = "simbricks/mem.hh"

    port = ResponsePort("Port to access the memory from CPU/Caches")

    listen = Param.Bool(False, "Open listening instead of connecting")
    uxsocket_path = Param.String("unix socket path")
    shm_path = Param.String("", "Shared memory path")
    sync = Param.Bool(False, "Synchronize over Ethernet")
    poll_interval = Param.Latency("100us", "poll interval size (unsync only)")
    sync_tx_interval = Param.Latency("500ns", "interval between syncs")
    link_latency = Param.Latency("500ns", "Ethernet latency")

    static_as_id = Param.UInt64(0x0, "Static address space ID for requests")
    base_address = Param.Addr("Memory Base Address")
    size = Param.Addr("Memory Size")


class SimBricksPciBar(PciBar):
    type = "SimBricksPciBar"
    cxx_class = "gem5::simbricks::pci::Bar"
    cxx_header = "simbricks/pci_bar.hh"


class SimBricksPci(PciEndpoint):
    type = "SimBricksPci"
    cxx_class = "gem5::simbricks::pci::Device"
    cxx_header = "simbricks/pci.hh"

    listen = Param.Bool(False, "Open listening instead of connecting")
    uxsocket_path = Param.String("unix socket path")
    shm_path = Param.String("", "Shared memory path")
    sync = Param.Bool(False, "Synchronize over PCI")
    poll_interval = Param.Latency("100us", "poll interval size (unsync only)")
    sync_tx_interval = Param.Latency("500ns", "interval between syncs")
    link_latency = Param.Latency("500ns", "PCI latency")

    BAR0 = SimBricksPciBar()
    BAR1 = SimBricksPciBar()
    BAR2 = SimBricksPciBar()
    BAR3 = SimBricksPciBar()
    BAR4 = SimBricksPciBar()
    BAR5 = SimBricksPciBar()

    Status = 0x0290
    MaximumLatency = 0x00
    MinimumGrant = 0xFF
    SubsystemID = 0x1008
    SubsystemVendorID = 0x8086

    # defaults to avoid gem5 erroring out
    VendorID = 0x0001
    DeviceID = 0x0001


class SimBricksPciHost(PciHost):
    """SimBricks PCIe adapter for the device side of the protocol.

    The mirror image of SimBricksPci: rather than representing a remote device
    inside a local host, this represents a remote host for a local gem5 PCI
    device model, so that the device can be simulated on its own and attached
    to a host simulated elsewhere.

    The device registers with this object as it would with any PCI host. The
    adapter enumerates it (sizing and assigning BARs, discovering MSI/MSI-X),
    reports what it found to the peer as the SimBricks device intro, turns the
    incoming MMIO accesses into local PIO accesses, and forwards the device's
    DMA and interrupts back over the channel.
    """

    type = "SimBricksPciHost"
    cxx_class = "gem5::simbricks::pci_host::Host"
    cxx_header = "simbricks/pci_host.hh"

    system = Param.System(Parent.any, "System this adapter belongs to")

    pio = RequestPort("Injects the accesses received from the remote host")
    dma = ResponsePort("Terminates the DMA traffic of the local device")

    # The device's DMA is bound straight to `dma` rather than routed over the
    # PCI bus. Routing it would be actively wrong: DMA addresses belong to the
    # remote host's address space and would sooner or later alias one of the
    # BAR windows the adapter hands out locally, at which point the bus
    # delivers a host memory access back to the device.
    #
    # That leaves the bus with no upstream traffic of its own, so its default
    # port ends at this responder instead. Anything arriving here is a local
    # access that decoded to nothing, which is a bug in the address map rather
    # than something to forward, so it gets an error response.
    stray_responder = Param.IsaFake(
        BadAddr(), "Answers local accesses that decode to no device"
    )

    # The device side of a SimBricks PCIe channel listens by convention.
    listen = Param.Bool(True, "Open listening instead of connecting")
    uxsocket_path = Param.String("unix socket path")
    shm_path = Param.String("", "Shared memory path")
    sync = Param.Bool(False, "Synchronize over PCI")
    poll_interval = Param.Latency("100us", "poll interval size (unsync only)")
    sync_tx_interval = Param.Latency("500ns", "interval between syncs")
    link_latency = Param.Latency("500ns", "PCI latency")

    # Local address map. None of these addresses ever leave this gem5
    # instance: the remote host assigns its own and the protocol only carries
    # (bar, offset) pairs. They only have to be free of collisions here, and
    # the config space must not start at address 0 -- some device models drop
    # ranges starting at 0 on the assumption they are unassigned.
    bus_num = Param.UInt8(0, "PCI bus number of the local device")
    conf_base = Param.Addr(0x1000000, "Config space base address")
    conf_size = Param.Addr(0x1000000, "Config space size")
    conf_device_bits = Param.UInt8(
        12, "Number of bits used as an offset into a device's config space"
    )

    pci_pio_base = Param.Addr(0x2000000, "Base address for PCI IO accesses")
    pci_mem_base = Param.Addr(0, "Base address for PCI memory accesses")
    pci_dma_base = Param.Addr(0, "Base address for DMA memory accesses")

    bar_mem32_base = Param.Addr(
        0x10000000, "First PCI memory address handed out to a 32 bit BAR"
    )
    bar_mem64_base = Param.Addr(
        0x100000000, "First PCI memory address handed out to a 64 bit BAR"
    )
    bar_io_base = Param.Addr(0x10000, "First PCI IO address handed out to a BAR")

    # Window the adapter points the device's MSI/MSI-X vectors at, in the
    # remote host's address space. Writes landing here become interrupt
    # messages instead of DMA. 0xfee00000 is the x86 MSI window, which no host
    # backs with memory.
    intr_doorbell_addr = Param.Addr(0xFEE00000, "Interrupt doorbell base")
    intr_doorbell_size = Param.Addr(0x100000, "Interrupt doorbell size")
    program_msix_table = Param.Bool(
        True,
        "Program the device's MSI-X table when the host enables MSI-X. Turn "
        "off for devices that do not implement a standard table in their BAR.",
    )

    def attachBus(self, pci_bus):
        """Wire this adapter into a PciBus in place of a platform PCI host."""
        pci_bus.default = self.down_response_port()
        pci_bus.cpu_side_ports = self.down_request_port()
        pci_bus.config_error_port = self.config_error.pio

        # Unlike a platform PCI host there is no system bus above us: the
        # adapter sources the requests going downstream itself, and the only
        # thing coming back up is the stray traffic described above.
        self.pio = self.up_response_port()
        self.stray_responder.pio = self.up_request_port()

    def attachDevice(self, pci_bus, device, bind_dma=True):
        pci_bus.mem_side_ports = device.pio
        # The device's DMA goes straight to the adapter rather than back
        # through the bus: host physical addresses can alias the BAR windows
        # assigned on this side, and a request that hits one would be routed
        # into the device instead of out to the host.
        #
        # A device built from several engines has a DMA port per engine (gem5's
        # AMD GPU has a dozen); those need a crossbar of their own in front of
        # `dma`, so the caller binds it and passes bind_dma=False.
        if bind_dma:
            self.dma = device.dma
