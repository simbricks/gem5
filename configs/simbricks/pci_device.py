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

"""Run a gem5 PCI device model as a SimBricks PCIe device.

Builds a system holding nothing but one of the device models below and the
SimBricks adapter fronting it, so the device can be driven by a host simulated
elsewhere:

    gem5.fast configs/simbricks/pci_device.py \\
        --device=e1000 \\
        --simbricks-pci-dev=listen:/tmp/sb-pci:/dev/shm/sb-pci:sync

A device needing more setup than these (an AMD GPU, for instance) belongs in
its own config script, calling pci_host.attach_simbricks_device() rather than
extending the --device table.
"""

import argparse

from m5.objects import *

from pci_host import add_channel_options, attach_simbricks_device, run
from simbricks_url import parse_simbricks_url


def make_virtio(system, args):
    """A stub VirtIO device. It has a single BAR and raises INTx, which makes
    it the cheapest way to check that a channel comes up end to end."""
    return PciVirtIO(
        pci_dev=0,
        pci_func=0,
        InterruptPin=1,
        InterruptLine=16,
        vio=VirtIODummyDevice(),
    )


def make_e1000(system, args):
    """Intel 82540 NIC. Its Ethernet side has to go somewhere: either a second
    SimBricks channel (--simbricks-eth) or a tap stub (--eth-tap-port)."""
    device = IGbE_e1000(
        pci_dev=0, pci_func=0, InterruptPin=1, InterruptLine=16
    )

    if args.simbricks_eth:
        system.simbricks_eth = SimBricksEthernet(
            **parse_simbricks_url(args.simbricks_eth)
        )
        system.simbricks_eth.int0 = device.interface
    else:
        system.eth_tap = EtherTapStub(port=args.eth_tap_port)
        system.eth_tap.tap = device.interface

    return device


DEVICES = {"virtio": make_virtio, "e1000": make_e1000}


def build_system(args):
    system = System()
    system.mem_mode = "timing"
    system.cache_line_size = 64

    system.voltage_domain = VoltageDomain(voltage="1.0V")
    system.clk_domain = SrcClockDomain(
        clock=args.sys_clock, voltage_domain=system.voltage_domain
    )

    system.device = DEVICES[args.device](system, args)
    attach_simbricks_device(system, system.device, args.simbricks_pci_dev)

    return system


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_channel_options(parser)
    parser.add_argument(
        "--device",
        choices=sorted(DEVICES.keys()),
        default="virtio",
        help="PCI device model to expose over the SimBricks channel",
    )
    parser.add_argument(
        "--simbricks-eth",
        default=None,
        help="SimBricks URL of the Ethernet channel, for network devices",
    )
    parser.add_argument(
        "--eth-tap-port",
        type=int,
        default=3500,
        help="Tap stub port used when a network device has no SimBricks "
        "Ethernet channel",
    )
    parser.add_argument("--sys-clock", default="1GHz")
    args = parser.parse_args()

    run(args, build_system(args), full_system=False)


# gem5 names the config script's module "__m5_main__".
if __name__ == "__m5_main__":
    main()
