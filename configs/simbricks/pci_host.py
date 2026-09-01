# Copyright 2026 Max Planck Institute for Software Systems,
# National University of Singapore, and SimBricks UG (haftungsbeschränkt)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
# CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
# TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

"""Attach a gem5 PCI device model to a SimBricks PCIe channel.

The counterpart of configs/simbricks/simbricks.py: instead of a full system
that talks to devices simulated elsewhere, this fronts one local PCI device
model with a SimBricks adapter, so the device can be attached to a host
simulated by QEMU, another gem5, or anything else that speaks the host half of
the SimBricks PCIe protocol.

Such a system has no CPU and no memory: all MMIO originates at the remote host
and all DMA ends up there. Config scripts building a device call
attach_simbricks_device() to front it; pci_device.py is one.
"""

import m5
from m5.objects import *

from simbricks_url import parse_simbricks_url


def add_channel_options(parser):
    """The arguments every script putting a device on a channel takes."""
    parser.add_argument(
        "--simbricks-pci-dev",
        required=True,
        help="SimBricks URL of the PCIe channel to the host",
    )
    parser.add_argument(
        "--max-tick",
        type=int,
        default=m5.MaxTick,
        help="Stop after this many ticks",
    )


def run(args, system, full_system):
    """Instantiate `system` and simulate until something ends it."""
    root = Root(full_system=full_system, system=system)

    m5.instantiate()

    print("Starting simulation")
    event = m5.simulate(args.max_tick)
    print(f"Exiting @ tick {m5.curTick()} because {event.getCause()}")


def attach_simbricks_device(system, device, url, bind_dma=True, **kwargs):
    """Attach a PCI device model to a SimBricks PCIe channel.

    Creates the PCI bus and the adapter and wires all three together. Extra
    keyword arguments go to SimBricksPciHost. `device` must not have its
    `upstream` set, and cannot share the adapter: a channel carries one device.

    `bind_dma` binds the device's own `dma` port to the adapter. A device with
    several -- gem5's AMD GPU has a dozen -- needs a crossbar in between: pass
    False and bind `simbricks_pci.dma` yourself.
    """
    params = parse_simbricks_url(url)
    params.update(kwargs)

    system.pci_bus = PciBus()
    system.simbricks_pci = SimBricksPciHost(**params)
    system.simbricks_pci.attachBus(system.pci_bus)

    device.upstream = system.simbricks_pci
    system.simbricks_pci.attachDevice(system.pci_bus, device, bind_dma=bind_dma)

    # Nothing else in this system sources memory traffic, but gem5 insists on
    # the system port being connected.
    system.system_port = system.pci_bus.cpu_side_ports

    return system.simbricks_pci
