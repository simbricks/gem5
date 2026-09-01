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

"""Run gem5's AMD GPU model as a SimBricks PCIe device.

gem5 ships the GPU as part of GPUFS, in one simulation with an x86 host and its
Linux. This config takes the GPU out of that and puts it behind the SimBricks
device-side PCIe adapter, so the host running the amdgpu driver is a separate
simulator -- QEMU, say -- at the other end of a channel.

    gem5.opt configs/simbricks/amd_gpu.py \\
        --gpu-device=MI200 \\
        --simbricks-pci-dev=listen:/tmp/sb-gpu:/dev/shm/sb-gpu

Where the memory goes
---------------------
GPUFS splits the GPU across a disjoint Ruby system: a GPU-side network reaching
VRAM, and a CPU-side one reaching host DRAM. Disjoint_VIPER.create() decides by
device type, and that split is exactly the SimBricks split. Host memory is not
in this simulation, so the GPU-side network stays as GPUFS builds it, while the
CPU-side one is not built at all: its ports go to a crossbar feeding the
adapter's DMA port, and every access on them becomes a SimBricks DMA request.

There is no CPU in any meaningful sense. One is instantiated switched-out
because Shader::init() dereferences its `cpu_pointer`; it never executes an
instruction. See make_idle_cpu().

What the guest still has to do
------------------------------
The driver reads the VBIOS from the legacy ROM shadow at physical 0xC0000,
which is *host* memory. The guest has to stage a ROM image there before
modprobe; simbricks-amdgpu-sys-py installs `simbricks-load-amdgpu` for it.

Note: The host must present a PCI Express endpoint
"""

import argparse
import math
import sys

from m5.objects import *
from m5.util import (
    addToPath,
    panic,
)

addToPath("../")

from common import (
    GPUTLBConfig,
    GPUTLBOptions,
    Options,
)

from example.gpufs.amd import AmdGPUOptions
from example.gpufs.DisjointNetwork import DisjointSimple
from example.gpufs.system.amdgpu import createGPU
from ruby import Ruby
from ruby.GPU_VIPER import (
    construct_gpudirs,
    construct_scalars,
    construct_sqcs,
    construct_tccs,
    construct_tcps,
)
from pci_host import add_channel_options, attach_simbricks_device, run

# ---------------------------------------------------------------------------
# Per-device tables, lifted from configs/example/gpufs so the two stay
# comparable. MMIO bases come from the driver's asic_reg headers.
# ---------------------------------------------------------------------------

SDMA_MMIO = {
    "Vega10": ([0x4980, 0x5180], 0x800),
    "MI100": (
        [0x4980, 0x6180, 0x78000, 0x79000, 0x7A000, 0x7B000, 0x7C000, 0x7D000],
        0x1000,
    ),
    "MI200": ([0x4980, 0x6180, 0x78000, 0x79000, 0x7A000], 0x1000),
    "MI300X": (
        [
            0x4980, 0x6180, 0x65000, 0x66000,
            0x84980, 0x86180, 0xE5000, 0xE6000,
            0x104980, 0x106180, 0x165000, 0x166000,
            0x184980, 0x186180, 0x1E5000, 0x1E6000,
        ],
        0x1000,
    ),
}
SDMA_MMIO["MI355X"] = SDMA_MMIO["MI300X"]

# PM4 packet processor MMIO windows. One before MI300X; later parts have one
# per XCD, at the offsets the IP discovery file names.
PM4_MMIO = {
    "MI300X": [
        0xC000, 0x4C000, 0x8C000, 0xCC000,
        0x10C000, 0x14C000, 0x18C000, 0x1CC000,
    ]
}
PM4_MMIO["MI355X"] = PM4_MMIO["MI300X"]

# (DeviceID, SubsystemID). SubsystemVendorID is 0x1002 throughout.
DEVICE_IDS = {
    "Vega10": (0x6863, None),
    "MI100": (0x738C, 0x0C34),
    "MI200": (0x740F, 0x0C34),
    "MI300X": (0x74A1, 0x0C34),
    "MI355X": (0x75A0, 0x0C34),
}


def make_idle_cpu(system, args):
    """A CPU that exists only to be pointed at.

    Shader::init() dereferences `cpuPointer` unconditionally, so the GPU needs
    some BaseCPU -- in GPUFS the host's, which here is another simulator.
    `switched_out` keeps it from registering thread contexts or checking the
    memory mode, while its constructor still builds the ThreadContext. Its
    ports are connected only because gem5 refuses to instantiate one that is
    not.
    """
    cpu = AtomicSimpleCPU(
        clk_domain=system.clk_domain, cpu_id=0, switched_out=True
    )
    # Without this BaseCPU fatals on "Number of ISAs (0) ... does not equal
    # number of threads (1)".
    cpu.createThreads()
    # Onto the crossbar terminating the sub-devices' PIO ranges. Nothing
    # traverses it, but a crossbar with no CPU-side port fatals with "Storage
    # sizes must be positive" when sizing its two-dimensional stats.
    cpu.icache_port = system.iobus.cpu_side_ports
    cpu.dcache_port = system.iobus.cpu_side_ports
    # Deliberately no interrupt controller: a switched-out CPU registers no
    # thread contexts, and x86's local APIC asserts on having one as soon as
    # the crossbar asks for its address ranges.
    return cpu


def make_gpu_device(args, cmd_proc, device_ih, sdmas, pm4s, mem_mgr):
    """The AMDGPUDevice itself, with the PCI config the driver expects.

    A trimmed connectGPU(): same values, minus everything that reaches for
    system.pc, which does not exist here.
    """
    device_id, subsystem_id = DEVICE_IDS[args.gpu_device]

    gpu = AMDGPUDevice(pci_dev=args.pci_dev, pci_func=0)
    gpu.device_name = args.gpu_device
    gpu.DeviceID = device_id
    if subsystem_id is not None:
        gpu.SubsystemVendorID = 0x1002
        gpu.SubsystemID = subsystem_id
    if args.gpu_device in ("MI300X", "MI355X"):
        gpu.BAR5 = PciMemBar(size="2MiB")

    # gem5's default 0x280, plus 0x10: there is a capabilities list.
    gpu.Status = 0x0290
    # A single entry: PCI Express at 0x80, blank next pointer.
    gpu.PXCAPBaseOffset = 0x80
    gpu.CapabilityPtr = 0x80
    gpu.PXCAPCapId = 0x10
    # DevCap2 bits 7 and 8: 32- and 64-bit PCIe atomics. Bit 9 (128-bit CAS)
    # is left off, the driver does not look at it.
    gpu.PXCAPDevCap2 = 0x00000180
    # Bit 6: this device may request atomics from other PCI devices.
    gpu.PXCAPDevCtrl2 = 0x0040

    gpu.cp = cmd_proc
    gpu.device_ih = device_ih
    gpu.sdmas = sdmas
    gpu.pm4_pkt_procs = pm4s
    gpu.memory_manager = mem_mgr
    gpu.ipt_binary = args.gpu_ipt
    gpu.checkpoint_before_mmios = False

    return gpu


def make_gpu_blocks(system, args):
    """Build the GPU's engines and return them with their DMA/PIO ports."""
    if args.gpu_device not in DEVICE_IDS:
        panic(f"Unknown GPU device {args.gpu_device}")

    shader = createGPU(system, args)

    # HSA queues and the command processor. Nothing addresses pioAddr with a
    # remote host, but the SimObject wants a value.
    hsapp_pt_walker = VegaPagetableWalker()
    hsapp = HSAPacketProcessor(
        pioAddr=0xE0000000,
        numHWQueues=args.num_hw_queues,
        walker=hsapp_pt_walker,
    )
    dispatcher = GPUDispatcher()
    cp_pt_walker = VegaPagetableWalker()
    cmd_proc = GPUCommandProcessor(
        hsapp=hsapp,
        dispatcher=dispatcher,
        walker=cp_pt_walker,
        target_non_blit_kernel_id=args.skip_until_gpu_kernel,
    )
    shader.dispatcher = dispatcher
    shader.gpu_cmd_proc = cmd_proc

    device_ih = AMDGPUInterruptHandler()

    sdma_bases, sdma_size = SDMA_MMIO[args.gpu_device]
    sdma_pt_walkers = []
    sdmas = []
    for base in sdma_bases:
        walker = VegaPagetableWalker()
        sdma_pt_walkers.append(walker)
        sdmas.append(
            SDMAEngine(walker=walker, mmio_base=base, mmio_size=sdma_size)
        )

    pm4_bases = PM4_MMIO.get(args.gpu_device, [0xC000])
    pm4s = [
        PM4PacketProcessor(
            ip_id=i, mmio_range=AddrRange(start=base, end=base + 0x1000)
        )
        for i, base in enumerate(pm4_bases)
    ]

    mem_mgr = AMDGPUMemoryManager(cache_line_size=args.cacheline_size)

    gpu = make_gpu_device(args, cmd_proc, device_ih, sdmas, pm4s, mem_mgr)

    # The shader's path to host memory: the CPU-side Ruby network in GPUFS,
    # the SimBricks channel here.
    system_hub = AMDGPUSystemHub()
    shader.system_hub = system_hub

    # Reaching host memory: these become SimBricks DMA.
    host_dma = [hsapp, cmd_proc, device_ih, system_hub] + sdmas + pm4s
    # Reaching device memory: these stay on the local GPU Ruby network. Same
    # membership test Disjoint_VIPER.create() applies (gpu_dma_types).
    device_dma = [mem_mgr, hsapp_pt_walker, cp_pt_walker] + sdma_pt_walkers

    # PIO ranges of the sub-devices. Nothing drives them -- MMIO arrives
    # through the BARs -- but gem5 wants every ResponsePort terminated.
    pio_devices = [hsapp, cmd_proc, device_ih, system_hub] + sdmas + pm4s

    return shader, gpu, host_dma, device_dma, pio_devices


def connect_cu_ports(system, args, ruby):
    """Bind each compute unit's ports to its Ruby sequencers.

    GPUFS does this after Disjoint_VIPER.create() rather than inside it, so
    building the network is not enough: unbound CU memory ports segfault on
    first use, which is not at kernel launch but during the driver's memory
    setup, via AMDGPUDevice::writeFrame() -> ComputeUnit::sendInvL2().

    The index walks ruby._cpu_ports in the order the sequencers were appended:
    TCP coalescers, SQC, scalar. GPUFS starts partway in because its list
    begins with the CPU's; here there are none.
    """
    shader = system.cpu[1]
    cus = shader.CUs

    # Token ports, for back pressure. By type, not position: the TCP
    # coalescers are not guaranteed to come first.
    token_port_idx = 0
    for port in ruby._cpu_ports:
        if isinstance(port, VIPERCoalescer):
            cus[token_port_idx].gmTokenPort = port.gmTokenPort
            token_port_idx += 1

    idx = 0
    # wf_size uncoalesced requests per issue cycle, hence that many ports.
    for i in range(args.num_compute_units):
        for j in range(args.wf_size):
            cus[i].memory_port[j] = ruby._cpu_ports[idx].in_ports[j]
        idx += 1

    for i in range(args.num_compute_units):
        if i > 0 and not i % args.cu_per_sqc:
            idx += 1
        cus[i].sqc_port = ruby._cpu_ports[idx].in_ports
    idx += 1

    for i in range(args.num_compute_units):
        if i > 0 and not i % args.cu_per_scalar_cache:
            idx += 1
        cus[i].scalar_port = ruby._cpu_ports[idx].in_ports


def make_ruby(system, args, device_dma):
    """The GPU half of GPUFS's disjoint Ruby system.

    Disjoint_VIPER.create() builds both halves and then hardcodes
    `system.pc.south_bridge.gpu`, so it cannot be reused. This keeps its
    GPU-side sequence and drops the CPU side, which here is the remote host.
    """
    ruby = RubySystem()
    system.ruby = ruby
    ruby.network_gpu = DisjointSimple(ruby)
    ruby.block_size_bytes = args.cacheline_size
    ruby.number_of_virtual_networks = 11
    ruby.network_gpu.number_of_virtual_networks = 11

    tcp_seqs, tcp_cntrls = construct_tcps(args, system, ruby, ruby.network_gpu)
    sqc_seqs, sqc_cntrls = construct_sqcs(args, system, ruby, ruby.network_gpu)
    scalar_seqs, scalar_cntrls = construct_scalars(
        args, system, ruby, ruby.network_gpu
    )
    tcc_cntrls = construct_tccs(args, system, ruby, ruby.network_gpu)
    gpu_dirs, gpu_mem_ctrls = construct_gpudirs(
        args, system, ruby, ruby.network_gpu
    )

    for d in gpu_dirs:
        d.CPUonly = False
        d.GPUonly = True

    # Ruby DMA controllers for the ports that reach VRAM.
    dma_cntrls = []
    for i, dev in enumerate(device_dma):
        seq = DMASequencer(version=i, ruby_system=ruby)
        cntrl = GPU_VIPER_DMA_Controller(
            version=i, dma_sequencer=seq, ruby_system=ruby
        )
        # VegaPagetableWalker and AMDGPUMemoryManager both expose `port`.
        seq.in_ports = dev.port
        cntrl.requestToDir = MessageBuffer(buffer_size=0)
        cntrl.requestToDir.out_port = ruby.network_gpu.in_port
        cntrl.responseFromDir = MessageBuffer(buffer_size=0)
        cntrl.responseFromDir.in_port = ruby.network_gpu.out_port
        cntrl.mandatoryQueue = MessageBuffer(buffer_size=0)
        dma_cntrls.append(cntrl)
    system.dma_cntrls = dma_cntrls

    # Has to come after every controller exists: the topology is built from
    # the list.
    ruby.network_gpu.connectGPU(
        args,
        tcp_cntrls
        + sqc_cntrls
        + scalar_cntrls
        + tcc_cntrls
        + dma_cntrls
        + gpu_dirs,
    )

    # The sequencers Ruby has to know about. GPUFS also lists the CPU's;
    # there are none here.
    all_sequencers = tcp_seqs + sqc_seqs + scalar_seqs
    ruby._cpu_ports = all_sequencers
    ruby.num_of_sequencers = len(all_sequencers)

    connect_cu_ports(system, args, ruby)

    # Not part of the *system's* address map: the Self.all default would
    # sweep up the VRAM below, and there is no host DRAM on this side.
    system.memories = []

    # The device's VRAM: the AbstractMemory objects behind the GPU memory
    # controllers.
    vram = []
    for mem_ctrl in gpu_mem_ctrls:
        if hasattr(mem_ctrl, "dram"):
            vram.append(mem_ctrl.dram)
        else:
            vram.append(mem_ctrl)
        if hasattr(mem_ctrl, "dram_2"):
            vram.append(mem_ctrl.dram_2)
    system.device.memories = vram

    if args.access_backing_store:
        ruby.access_backing_store = True

    return ruby


def build_system(args):
    system = System()
    system.mem_mode = "timing"
    system.cache_line_size = args.cacheline_size

    system.voltage_domain = VoltageDomain(voltage=args.sys_voltage)
    system.clk_domain = SrcClockDomain(
        clock=args.sys_clock, voltage_domain=system.voltage_domain
    )

    # Host memory as this side sees it: one range covering everything, so any
    # DMA address routes to the adapter instead of falling off the crossbar.
    system.mem_ranges = [AddrRange(args.host_mem_size)]

    # Everything host-facing funnels through here into the adapter's DMA port.
    system.host_dma_bus = IOXBar(width=64)
    # Terminates the sub-devices' PIO ranges, which nothing drives.
    system.iobus = IOXBar(width=64)

    # Before the GPU: createGPU() reads system.cpu[0] for the cpu_pointer.
    system.cpu = [make_idle_cpu(system, args)]

    shader, gpu, host_dma, device_dma, pio_devices = make_gpu_blocks(
        system, args
    )
    system.device = gpu

    # Ruby treats the GPU's compute side as a CPU, and GPUFS appends it to
    # system.cpu so the sequencers find it by index.
    system.cpu.append(shader)

    for dev in pio_devices:
        dev.pio = system.iobus.mem_side_ports

    # Full-system TLBs for the SQC, scalar and vector data ports. This also
    # appends the L3 TLB's walker to system._dma_ports; it is device-side, so
    # it joins the GPU network like the others.
    args.full_system = True
    system._dma_ports = []
    GPUTLBConfig.config_tlb_hierarchy(args, system, 1, system.device, True)
    device_dma = device_dma + system._dma_ports

    ruby = make_ruby(system, args, device_dma)
    ruby.clk_domain = SrcClockDomain(
        clock=args.ruby_clock, voltage_domain=system.voltage_domain
    )

    # Host-facing DMA. All named `dma`, except the walkers and memory manager
    # handled above. The device itself is one: PciEndpoint is a DmaDevice.
    for dev in host_dma + [system.device]:
        dev.dma = system.host_dma_bus.cpu_side_ports

    adapter = attach_simbricks_device(
        system, system.device, args.simbricks_pci_dev, bind_dma=False
    )
    adapter.dma = system.host_dma_bus.mem_side_ports

    return system


def add_options(parser):
    add_channel_options(parser)
    parser.add_argument(
        "--gpu-device",
        default="MI200",
        choices=sorted(DEVICE_IDS.keys()),
        help="GPU model to simulate",
    )
    parser.add_argument(
        "--gpu-ipt",
        default="",
        help="IP discovery table to load (MI300X and later)",
    )
    parser.add_argument(
        "--pci-dev",
        type=int,
        default=0,
        help="PCI device number to report to the host",
    )
    parser.add_argument(
        "--host-mem-size",
        default="16GiB",
        help="Size of the host address range DMA may target. Only has to "
        "cover the addresses the host actually hands out.",
    )
    parser.add_argument(
        "--dgpu-mem-size", default="16GiB", help="dGPU physical memory size"
    )
    parser.add_argument(
        "--dgpu-num-dirs",
        type=int,
        default=1,
        help="Number of dGPU directories (memory controllers)",
    )
    parser.add_argument(
        "--dgpu-mem-type", default="HBM_1000_4H_1x128", help="VRAM model"
    )
    parser.add_argument(
        "--skip-until-gpu-kernel",
        type=int,
        default=0,
        help="Skip non-blit kernels until reaching this one",
    )
    parser.add_argument(
        "--gpu-progress-interval",
        type=int,
        default=0,
        help="Frequency in exec cycles of GPU progress prints",
    )
    parser.add_argument("--cpu-topology", default="Crossbar")
    parser.add_argument("--gpu-topology", default="Crossbar")
    # GPU_VIPER reads these but does not define them; runfs.py normally does.
    parser.add_argument("--tcp-rp", default="TreePLRURP")
    parser.add_argument("--tcc-rp", default="TreePLRURP")
    parser.add_argument("--sqc-rp", default="TreePLRURP")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    add_options(parser)
    Options.addCommonOptions(parser)
    Ruby.define_options(parser)
    AmdGPUOptions.addAmdGPUOptions(parser)
    GPUTLBOptions.tlb_options(parser)
    args = parser.parse_args()

    # Sizing that the protocol derives rather than the user choosing.
    n_cu = args.num_compute_units
    args.num_sqc = int(math.ceil(float(n_cu) / args.cu_per_sqc))
    args.num_scalar_cache = int(
        math.ceil(float(n_cu) / args.cu_per_scalar_cache)
    )

    system = build_system(args)

    # Full system for the GPU's sake -- device page tables rather than a
    # process address space -- but with nothing to boot.
    #
    # StubWorkload, not KernelWorkload with an empty object_file: the latter
    # only warns, then segfaults in byteOrder() the first time the driver
    # touches the frame aperture, since AbstractMemory::access() asks for the
    # guest byte order on every VRAM write.
    system.workload = StubWorkload()

    run(args, system, full_system=True)


if __name__ == "__m5_main__":
    main()
