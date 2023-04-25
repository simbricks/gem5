from __future__ import print_function
from __future__ import absolute_import

import argparse
import sys

import m5
from m5.defines import buildEnv
from m5.objects import *
from m5.util import addToPath, fatal, warn, convert
from m5.util.fdthelper import *
from gem5.isas import ISA
#from gem5.runtime import get_runtime_isa

addToPath("../")

from common.Benchmarks import *
from common import Simulation
from common import CacheConfig
from common import CpuConfig
from common import MemConfig
from common import ObjectList
from common.Caches import *
from common import Options


def malformedSimBricksUrl(s):
    print("Error: SimBricks URL", s, "is malformed")
    sys.exit(1)


# Parse SimBricks "URLs" in the following format:
# ADDR[ARGS]
# ADDR = connect:UX_SOCKET_PATH |
#        listen:UX_SOCKET_PATH:SHM_PATH
# ARGS = :sync | :link_latency=XX | :sync_interval=XX
def parseSimBricksUrl(s):
    out = {"sync": False}
    parts = s.split(":")
    if len(parts) < 2:
        malformedSimBricksUrl(s)

    if parts[0] == "connect":
        out["listen"] = False
        out["uxsocket_path"] = parts[1]
        parts = parts[2:]
    elif parts[0] == "listen":
        if len(parts) < 3:
            malformedSimBricksUrl(s)
        out["listen"] = True
        out["uxsocket_path"] = parts[1]
        out["shm_path"] = parts[2]
        parts = parts[3:]
    else:
        malformedSimBricksUrl(s)

    for p in parts:
        if p == "sync":
            out["sync"] = True
        elif p.startswith("sync_interval="):
            out["sync_tx_interval"] = p.split("=")[1]
        elif p.startswith("latency="):
            out["link_latency"] = p.split("=")[1]
        else:
            malformedSimBricksUrl(s)
    return out


class CowIdeDisk(IdeDisk):
    image = CowDiskImage(child=RawDiskImage(read_only=True), read_only=False)

    def childImage(self, ci):
        self.image.child.image_file = ci


def makeCowDisks(disk_paths):
    disks = []
    for disk_path in disk_paths:
        disk = CowIdeDisk(driveID="device0")
        disk.childImage(disk_path)
        disks.append(disk)
    return disks


class MemBus(SystemXBar):
    badaddr_responder = BadAddr()
    default = Self.badaddr_responder.pio
    snoop_filter = NULL


def fillInCmdline(mdesc, template, **kwargs):
    kwargs.setdefault("rootdev", mdesc.rootdev())
    kwargs.setdefault("mem", mdesc.mem())
    kwargs.setdefault("script", mdesc.script())
    return template % kwargs


def connectX86ClassicSystem(x86_sys, numCPUs):
    # Constants similar to x86_traits.hh
    IO_address_space_base = 0x8000000000000000
    pci_config_address_space_base = 0xC000000000000000
    interrupts_address_space_base = 0xA000000000000000
    APIC_range_size = 1 << 12

    x86_sys.membus = MemBus()

    # North Bridge
    x86_sys.iobus = IOXBar()
    x86_sys.bridge = Bridge(delay="50ns")
    x86_sys.bridge.mem_side_port = x86_sys.iobus.cpu_side_ports
    x86_sys.bridge.cpu_side_port = x86_sys.membus.mem_side_ports
    # Allow the bridge to pass through:
    #  1) kernel configured PCI device memory map address: address range
    #     [0xC0000000, 0xFFFF0000). (The upper 64kB are reserved for m5ops.)
    #  2) the bridge to pass through the IO APIC (two pages, already contained in 1),
    #  3) everything in the IO address range up to the local APIC, and
    #  4) then the entire PCI address space and beyond.
    x86_sys.bridge.ranges = [
        AddrRange(0xC0000000, 0xFFFF0000),
        AddrRange(IO_address_space_base, interrupts_address_space_base - 1),
        AddrRange(pci_config_address_space_base, Addr.max),
    ]

    # Create a bridge from the IO bus to the memory bus to allow access to
    # the local APIC (two pages)
    x86_sys.apicbridge = Bridge(delay="50ns")
    x86_sys.apicbridge.cpu_side_port = x86_sys.iobus.mem_side_ports
    x86_sys.apicbridge.mem_side_port = x86_sys.membus.cpu_side_ports
    x86_sys.apicbridge.ranges = [
        AddrRange(
            interrupts_address_space_base,
            interrupts_address_space_base + numCPUs * APIC_range_size - 1,
        )
    ]

    # connect the io bus
    x86_sys.pc.attachIO(x86_sys.iobus, [], x86_sys.membus)

    x86_sys.system_port = x86_sys.membus.cpu_side_ports


def makeX86System(mem_mode, numCPUs=1, mdesc=None, workload=None, Ruby=False):
    self = System()

    self.m5ops_base = 0xFFFF0000

    if workload is None:
        workload = X86FsWorkload()
    self.workload = workload

    if not mdesc:
        # generic system
        mdesc = SysConfig()
    self.readfile = mdesc.script()

    self.mem_mode = mem_mode

    # Physical memory
    # On the PC platform, the memory region 0xC0000000-0xFFFFFFFF is reserved
    # for various devices.  Hence, if the physical memory size is greater than
    # 3GB, we need to split it into two parts.
    excess_mem_size = convert.toMemorySize(mdesc.mem()) - convert.toMemorySize(
        "3GB"
    )
    if excess_mem_size <= 0:
        self.mem_ranges = [AddrRange(mdesc.mem())]
    else:
        warn(
            "Physical memory size specified is %s which is greater than "
            "3GB.  Twice the number of memory controllers would be "
            "created." % (mdesc.mem())
        )

        self.mem_ranges = [
            AddrRange("3GB"),
            AddrRange(Addr("4GB"), size=excess_mem_size),
        ]

    class SimBricksPc(Pc):
        def __init__(self):
            super(SimBricksPc, self).__init__()
            self._num_simbricks = 0
            self._num_simbricks_mem = 0
            self._devid_next = 0

        def add_simbricks_pci(self, url):
            print("adding simbricks pci:", url)
            params = parseSimBricksUrl(url)
            dev = SimBricksPci(
                pci_bus=0,
                pci_dev=self._devid_next,
                pci_func=0,
                InterruptLine=(16 + self._devid_next),
                InterruptPin=1,
                LegacyIOBase=0x8000000000000000,
                **params,
            )
            setattr(self, "simbricks_" + str(self._num_simbricks), dev)
            self._devid_next += 1
            self._num_simbricks += 1

        def add_simbricks_e1000_eth(self, url):
            print("adding simbricks eth:", url)
            params = parseSimBricksUrl(url)

            ethif = SimBricksEthernet(**params)
            setattr(self, "simbricks_ethif_" + str(self._num_simbricks), ethif)

            dev = IGbE_e1000(
                pci_bus=0,
                pci_dev=self._devid_next,
                pci_func=0,
                InterruptLine=(16 + self._devid_next),
                InterruptPin=1,
            )
            setattr(self, "simbricks_" + str(self._num_simbricks), dev)
            ethif.int0 = dev.interface

            self._devid_next += 1
            self._num_simbricks += 1

        def add_simbricks_mem(self, arg):
            [size, addr, as_id, url] = arg.split("@")
            print(
                f"adding simbricks mem: size={size} addr={addr} as={as_id} "
                f"url={url}"
            )
            params = parseSimBricksUrl(url)
            params["size"] = size
            params["base_address"] = addr
            params["static_as_id"] = as_id

            mem = SimBricksMem(**params)
            setattr(self, "simbricks_mem_" + str(self._num_simbricks_mem), mem)
            self._num_simbricks_mem += 1

        def attachIO(self, bus, dma_ports=[], membus=None):
            super(SimBricksPc, self).attachIO(bus, dma_ports)
            print(
                f"connecting {self._num_simbricks} pci & eth simbricks "
                "adapters"
            )
            for i in range(0, self._num_simbricks):
                dev = getattr(self, "simbricks_" + str(i))
                dev.pio = bus.mem_side_ports
                dev.dma = bus.cpu_side_ports
            print(
                f"connecting {self._num_simbricks_mem} mem simbricks "
                "adapters"
            )
            for i in range(0, self._num_simbricks_mem):
                mem = getattr(self, "simbricks_mem_" + str(i))
                mem.port = membus.mem_side_ports

    # Platform
    self.pc = SimBricksPc()

    # Add simbricks pci adapters as needed
    for url in args.simbricks_pci:
        self.pc.add_simbricks_pci(url)

    for url in args.simbricks_eth_e1000:
        self.pc.add_simbricks_e1000_eth(url)

    for url in args.simbricks_mem:
        self.pc.add_simbricks_mem(url)

    self.pc.com_1.device = Terminal(port=args.termport, outfile="stdoutput")

    # Create and connect the busses required by each memory system
    connectX86ClassicSystem(self, numCPUs)

    # Disks
    disks = makeCowDisks(mdesc.disks())
    self.pc.south_bridge.ide.disks = disks

    # Add in a Bios information structure.
    structures = [X86SMBiosBiosInformation()]
    workload.smbios_table.structures = structures

    # Set up the Intel MP table
    base_entries = []
    ext_entries = []
    madt_records = []
    for i in range(numCPUs):
        bp = X86IntelMPProcessor(
            local_apic_id=i,
            local_apic_version=0x14,
            enable=True,
            bootstrap=(i == 0),
        )
        base_entries.append(bp)
        lapic = X86ACPIMadtLAPIC(acpi_processor_id=i, apic_id=i, flags=1)
        madt_records.append(lapic)
    io_apic = X86IntelMPIOAPIC(
        id=numCPUs, version=0x11, enable=True, address=0xFEC00000
    )
    self.pc.south_bridge.io_apic.apic_id = io_apic.id
    base_entries.append(io_apic)
    madt_records.append(
        X86ACPIMadtIOAPIC(id=io_apic.id, address=io_apic.address, int_base=0)
    )
    # In gem5 Pc::calcPciConfigAddr(), it required "assert(bus==0)",
    # but linux kernel cannot config PCI device if it was not connected to
    # PCI bus, so we fix PCI bus id to 0, and ISA bus id to 1.
    pci_bus = X86IntelMPBus(bus_id=0, bus_type="PCI   ")
    base_entries.append(pci_bus)
    isa_bus = X86IntelMPBus(bus_id=1, bus_type="ISA   ")
    base_entries.append(isa_bus)
    connect_busses = X86IntelMPBusHierarchy(
        bus_id=1, subtractive_decode=True, parent_bus=0
    )
    ext_entries.append(connect_busses)
    for dev in range(0, 4):
        pci_dev_inta = X86IntelMPIOIntAssignment(
            interrupt_type="INT",
            polarity="ConformPolarity",
            trigger="ConformTrigger",
            source_bus_id=0,
            source_bus_irq=0 + (dev << 2),
            dest_io_apic_id=io_apic.id,
            dest_io_apic_intin=16 + dev,
        )
        base_entries.append(pci_dev_inta)
        pci_dev_inta_madt = X86ACPIMadtIntSourceOverride(
            bus_source=pci_dev_inta.source_bus_id,
            irq_source=pci_dev_inta.source_bus_irq,
            sys_int=pci_dev_inta.dest_io_apic_intin,
            flags=0,
        )
        madt_records.append(pci_dev_inta_madt)

    def assignISAInt(irq, apicPin):
        assign_8259_to_apic = X86IntelMPIOIntAssignment(
            interrupt_type="ExtInt",
            polarity="ConformPolarity",
            trigger="ConformTrigger",
            source_bus_id=1,
            source_bus_irq=irq,
            dest_io_apic_id=io_apic.id,
            dest_io_apic_intin=0,
        )
        base_entries.append(assign_8259_to_apic)
        assign_to_apic = X86IntelMPIOIntAssignment(
            interrupt_type="INT",
            polarity="ConformPolarity",
            trigger="ConformTrigger",
            source_bus_id=1,
            source_bus_irq=irq,
            dest_io_apic_id=io_apic.id,
            dest_io_apic_intin=apicPin,
        )
        base_entries.append(assign_to_apic)
        # acpi
        assign_to_apic_acpi = X86ACPIMadtIntSourceOverride(
            bus_source=1, irq_source=irq, sys_int=apicPin, flags=0
        )
        madt_records.append(assign_to_apic_acpi)

    assignISAInt(0, 2)
    assignISAInt(1, 1)
    for i in range(3, 15):
        assignISAInt(i, i)
    workload.intel_mp_table.base_entries = base_entries
    workload.intel_mp_table.ext_entries = ext_entries

    madt = X86ACPIMadt(
        local_apic_address=0, records=madt_records, oem_id="madt"
    )
    workload.acpi_description_table_pointer.rsdt.entries.append(madt)
    workload.acpi_description_table_pointer.xsdt.entries.append(madt)
    workload.acpi_description_table_pointer.oem_id = "gem5"
    workload.acpi_description_table_pointer.rsdt.oem_id = "gem5"
    workload.acpi_description_table_pointer.xsdt.oem_id = "gem5"
    return self


def makeLinuxX86System(
    mem_mode, numCPUs=1, mdesc=None, Ruby=False, cmdline=None
):
    # Build up the x86 system and then specialize it for Linux
    self = makeX86System(mem_mode, numCPUs, mdesc, X86FsLinux(), Ruby)

    # We assume below that there's at least 1MB of memory. We'll require 2
    # just to avoid corner cases.
    phys_mem_size = sum([r.size() for r in self.mem_ranges])
    assert phys_mem_size >= 0x200000
    assert len(self.mem_ranges) <= 2

    entries = [
        # Mark the first megabyte of memory as reserved
        X86E820Entry(addr=0, size="639kB", range_type=1),
        X86E820Entry(addr=0x9FC00, size="385kB", range_type=2),
        # Mark the rest of physical memory as available
        X86E820Entry(
            addr=0x100000,
            size="%dB" % (self.mem_ranges[0].size() - 0x100000),
            range_type=1,
        ),
    ]

    # Mark [mem_size, 3GB) as reserved if memory less than 3GB, which force
    # IO devices to be mapped to [0xC0000000, 0xFFFF0000). Requests to this
    # specific range can pass though bridge to iobus.
    if len(self.mem_ranges) == 1:
        entries.append(
            X86E820Entry(
                addr=self.mem_ranges[0].size(),
                size="%dB" % (0xC0000000 - self.mem_ranges[0].size()),
                range_type=2,
            )
        )

    # Reserve the last 16kB of the 32-bit address space for the m5op interface
    entries.append(X86E820Entry(addr=0xFFFF0000, size="64kB", range_type=2))

    # In case the physical memory is greater than 3GB, we split it into two
    # parts and add a separate e820 entry for the second part.  This entry
    # starts at 0x100000000,  which is the first address after the space
    # reserved for devices.
    if len(self.mem_ranges) == 2:
        entries.append(
            X86E820Entry(
                addr=0x100000000,
                size="%dB" % (self.mem_ranges[1].size()),
                range_type=1,
            )
        )

    self.workload.e820_table.entries = entries

    # Command line
    if not cmdline:
        cmdline = "earlyprintk=ttyS0 console=ttyS0 root=/dev/sda1 no_timer_check memory_corruption_check=0 random.trust_cpu=on init=/home/ubuntu/guestinit.sh"
    self.workload.command_line = fillInCmdline(mdesc, cmdline)
    if args.command_line_append:
        self.workload.command_line += " " + args.command_line_append
    return self


def cmd_line_template():
    if args.command_line and args.command_line_file:
        print(
            "Error: --command-line and --command-line-file are "
            "mutually exclusive"
        )
        sys.exit(1)
    if args.command_line:
        return args.command_line
    if args.command_line_file:
        return open(args.command_line_file).read().strip()
    return None


def build_system(np):
    cmdline = cmd_line_template()

    sys = makeLinuxX86System(
        test_mem_mode, np, bm[0], args.ruby, cmdline=cmdline
    )

    # Set the cache line size for the entire system
    sys.cache_line_size = args.cacheline_size

    # Create a top-level voltage domain
    sys.voltage_domain = VoltageDomain(voltage=args.sys_voltage)

    # Create a source clock for the system and set the clock period
    sys.clk_domain = SrcClockDomain(
        clock=args.sys_clock, voltage_domain=sys.voltage_domain
    )

    # Create a CPU voltage domain
    sys.cpu_voltage_domain = VoltageDomain()

    # Create a source clock for the CPUs and set the clock period
    sys.cpu_clk_domain = SrcClockDomain(
        clock=args.cpu_clock, voltage_domain=sys.cpu_voltage_domain
    )

    if args.kernel is not None:
        sys.workload.object_file = binary(args.kernel)

    if args.script is not None:
        sys.readfile = args.script

    sys.init_param = args.init_param

    # For now, assign all the CPUs to the same clock domain
    sys.cpu = [
        TestCPUClass(clk_domain=sys.cpu_clk_domain, cpu_id=i)
        for i in range(np)
    ]

    if ObjectList.is_kvm_cpu(TestCPUClass) or ObjectList.is_kvm_cpu(
        FutureClass
    ):
        sys.kvm_vm = KvmVM()

    CacheConfig.config_cache(args, sys)
    # if args.caches and args.l3cache and args.ddio_enabled:
    #     # By default the IOCache runs at the system clock
    #     sys.iocache = IOCache(addr_ranges = sys.mem_ranges,
    #                           is_iocache = True,
    #                           ddio_enabled = True,
    #                           assoc = 16, tag_latency = 2,
    #                           data_latency = 2, response_latency = 2,
    #                           write_buffers = 64)
    #     sys.iocache.cpu_side = sys.iobus.mem_side_ports
    #     sys.iocache.mem_side = sys.tol3bus.cpu_side_ports

    if args.caches or args.l2cache:
        # By default the IOCache runs at the system clock
        sys.iocache = IOCache(
            addr_ranges=sys.mem_ranges,
            assoc=16,
            tag_latency=2,
            data_latency=2,
            response_latency=2,
            write_buffers=64,
        )
        sys.iocache.cpu_side = sys.iobus.mem_side_ports
        sys.iocache.mem_side = sys.tol2bus.cpu_side_ports
    elif not args.external_memory_system:
        sys.iobridge = Bridge(delay="50ns", ranges=sys.mem_ranges)
        sys.iobridge.cpu_side_port = sys.iobus.mem_side_ports
        sys.iobridge.mem_side_port = sys.membus.cpu_side_ports

    # Sanity check
    if args.simpoint_profile:
        if not ObjectList.is_noncaching_cpu(TestCPUClass):
            fatal("SimPoint generation should be done with atomic cpu")
        if np > 1:
            fatal("SimPoint generation not supported with more than one CPUs")

    for i in range(np):
        if args.simpoint_profile:
            sys.cpu[i].addSimPointProbe(args.simpoint_interval)
        if args.checker:
            sys.cpu[i].addCheckerCpu()
        if not ObjectList.is_kvm_cpu(TestCPUClass):
            if args.bp_type:
                bpClass = ObjectList.bp_list.get(args.bp_type)
                sys.cpu[i].branchPred = bpClass()
            if args.indirect_bp_type:
                IndirectBPClass = ObjectList.indirect_bp_list.get(
                    args.indirect_bp_type
                )
                sys.cpu[i].branchPred.indirectBranchPred = IndirectBPClass()
        sys.cpu[i].createThreads()

    # If elastic tracing is enabled when not restoring from checkpoint and
    # when not fast forwarding using the atomic cpu, then check that the
    # TestCPUClass is DerivO3CPU or inherits from DerivO3CPU. If the check
    # passes then attach the elastic trace probe.
    # If restoring from checkpoint or fast forwarding, the code that does this for
    # FutureCPUClass is in the Simulation module. If the check passes then the
    # elastic trace probe is attached to the switch CPUs.
    if (
        args.elastic_trace_en
        and args.checkpoint_restore == None
        and not args.fast_forward
    ):
        CpuConfig.config_etrace(TestCPUClass, sys.cpu, args)

    MemConfig.config_mem(args, sys)

    return sys


# Add options
parser = argparse.ArgumentParser()
Options.addCommonOptions(parser)
Options.addFSOptions(parser)

parser.add_argument(
    "--termport",
    action="store",
    type=int,
    default=3456,
    help="port for terminal to listen on",
)
parser.add_argument(
    "--simbricks-pci",
    action="append",
    type=str,
    default=[],
    help="Simbricks PCI URLs to connect to",
)
parser.add_argument(
    "--simbricks-eth-e1000",
    action="append",
    type=str,
    default=[],
    help="Simbricks Ethernet URLs to connect e1000 adapters to",
)
parser.add_argument(
    "--simbricks-mem",
    action="append",
    type=str,
    default=[],
    help="Simbricks Mem blocks to add: SIZE@ADDR@ASID@URL",
)
parser.add_argument(
    "--command-line-append",
    action="store",
    type=str,
    default="",
    help="append to kernel command line",
)

args = parser.parse_args()


# system under test can be any CPU
(TestCPUClass, test_mem_mode, FutureClass) = Simulation.setCPUClass(args)

# Match the memories with the CPUs, based on the options for the test system
TestMemClass = Simulation.setMemClass(args)

bm = [
    SysConfig(
        disks=args.disk_image,
        rootdev=args.root_device,
        mem=args.mem_size,
        os_type=args.os_type,
    )
]
np = args.num_cpus
sys = build_system(np)
root = Root(full_system=True, system=sys)

if args.timesync:
    root.time_sync_enable = True

if args.frame_capture:
    VncServer.frame_capture = True

Simulation.setWorkCountOptions(sys, args)
Simulation.run(args, root, sys, FutureClass)
