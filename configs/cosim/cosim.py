from __future__ import print_function
from __future__ import absolute_import

import optparse
import sys

import m5
from m5.defines import buildEnv
from m5.objects import *
from m5.util import addToPath, fatal, warn, convert
from m5.util.fdthelper import *

addToPath('../')

from common.Benchmarks import *
from common import Simulation
from common import CacheConfig
from common import CpuConfig
from common import MemConfig
from common import ObjectList
from common.Caches import *
from common import Options

class CowIdeDisk(IdeDisk):
    image = CowDiskImage(child=RawDiskImage(read_only=True),
                         read_only=False)

    def childImage(self, ci):
        self.image.child.image_file = ci

def makeCowDisks(disk_paths):
    disks = []
    for disk_path in disk_paths:
        disk = CowIdeDisk(driveID='master')
        disk.childImage(disk_path);
        disks.append(disk)
    return disks

class MemBus(SystemXBar):
    badaddr_responder = BadAddr()
    default = Self.badaddr_responder.pio

def fillInCmdline(mdesc, template, **kwargs):
    kwargs.setdefault('rootdev', mdesc.rootdev())
    kwargs.setdefault('mem', mdesc.mem())
    kwargs.setdefault('script', mdesc.script())
    return template % kwargs

def connectX86ClassicSystem(x86_sys, numCPUs):
    # Constants similar to x86_traits.hh
    IO_address_space_base = 0x8000000000000000
    pci_config_address_space_base = 0xc000000000000000
    interrupts_address_space_base = 0xa000000000000000
    APIC_range_size = 1 << 12;

    x86_sys.membus = MemBus()

    # North Bridge
    x86_sys.iobus = IOXBar()
    x86_sys.bridge = Bridge(delay='50ns')
    x86_sys.bridge.master = x86_sys.iobus.slave
    x86_sys.bridge.slave = x86_sys.membus.master
    # Allow the bridge to pass through:
    #  1) kernel configured PCI device memory map address: address range
    #     [0xC0000000, 0xFFFF0000). (The upper 64kB are reserved for m5ops.)
    #  2) the bridge to pass through the IO APIC (two pages, already contained in 1),
    #  3) everything in the IO address range up to the local APIC, and
    #  4) then the entire PCI address space and beyond.
    x86_sys.bridge.ranges = \
        [
        AddrRange(0xC0000000, 0xFFFF0000),
        AddrRange(IO_address_space_base,
                  interrupts_address_space_base - 1),
        AddrRange(pci_config_address_space_base,
                  Addr.max)
        ]

    # Create a bridge from the IO bus to the memory bus to allow access to
    # the local APIC (two pages)
    x86_sys.apicbridge = Bridge(delay='50ns')
    x86_sys.apicbridge.slave = x86_sys.iobus.master
    x86_sys.apicbridge.master = x86_sys.membus.slave
    x86_sys.apicbridge.ranges = [AddrRange(interrupts_address_space_base,
                                           interrupts_address_space_base +
                                           numCPUs * APIC_range_size
                                           - 1)]

    # connect the io bus
    x86_sys.pc.attachIO(x86_sys.iobus)

    x86_sys.system_port = x86_sys.membus.slave

def makeX86System(mem_mode, numCPUs=1, mdesc=None, workload=None, Ruby=False):
    self = System()

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
    excess_mem_size = \
        convert.toMemorySize(mdesc.mem()) - convert.toMemorySize('3GB')
    if excess_mem_size <= 0:
        self.mem_ranges = [AddrRange(mdesc.mem())]
    else:
        warn("Physical memory size specified is %s which is greater than " \
             "3GB.  Twice the number of memory controllers would be " \
             "created."  % (mdesc.mem()))

        self.mem_ranges = [AddrRange('3GB'),
            AddrRange(Addr('4GB'), size = excess_mem_size)]

    class PCIPc(Pc):
        ethernet = Cosim(pci_bus=0, pci_dev=2, pci_func=0,
                         InterruptLine=15, InterruptPin=1,
                         BAR0=0xC0000000,
                         CapabilityPtr=64,
                         MSICAPBaseOffset=64,
                         MSICAPCapId=0x5,
                         MSICAPMsgCtrl=0x8a,
                         uxsocket_path=options.cosim_pci,
                         shm_path=options.cosim_shm,
                         sync=options.cosim_sync,
                         poll_interval='100us',
                         pci_asychrony='1us')

        def attachIO(self, bus, dma_ports = []):
            super(PCIPc, self).attachIO(bus, dma_ports)
            self.ethernet.pio = bus.master
            self.ethernet.dma = bus.slave


    # Platform
    self.pc = PCIPc()
    self.pc.com_1.device = Terminal(port = options.termport, outfile =
            'stdoutput')

    # Create and connect the busses required by each memory system
    connectX86ClassicSystem(self, numCPUs)

    self.intrctrl = IntrControl()

    # Disks
    disks = makeCowDisks(mdesc.disks())
    self.pc.south_bridge.ide.disks = disks

    # Add in a Bios information structure.
    structures = [X86SMBiosBiosInformation()]
    workload.smbios_table.structures = structures

    # Set up the Intel MP table
    base_entries = []
    ext_entries = []
    for i in range(numCPUs):
        bp = X86IntelMPProcessor(
                local_apic_id = i,
                local_apic_version = 0x14,
                enable = True,
                bootstrap = (i == 0))
        base_entries.append(bp)
    io_apic = X86IntelMPIOAPIC(
            id = numCPUs,
            version = 0x11,
            enable = True,
            address = 0xfec00000)
    self.pc.south_bridge.io_apic.apic_id = io_apic.id
    base_entries.append(io_apic)
    # In gem5 Pc::calcPciConfigAddr(), it required "assert(bus==0)",
    # but linux kernel cannot config PCI device if it was not connected to
    # PCI bus, so we fix PCI bus id to 0, and ISA bus id to 1.
    pci_bus = X86IntelMPBus(bus_id = 0, bus_type='PCI   ')
    base_entries.append(pci_bus)
    isa_bus = X86IntelMPBus(bus_id = 1, bus_type='ISA   ')
    base_entries.append(isa_bus)
    connect_busses = X86IntelMPBusHierarchy(bus_id=1,
            subtractive_decode=True, parent_bus=0)
    ext_entries.append(connect_busses)
    pci_dev2_inta = X86IntelMPIOIntAssignment(
            interrupt_type = 'INT',
            polarity = 'ConformPolarity',
            trigger = 'ConformTrigger',
            source_bus_id = 0,
            source_bus_irq = 0 + (2 << 2),
            dest_io_apic_id = io_apic.id,
            dest_io_apic_intin = 17)
    base_entries.append(pci_dev2_inta)
    pci_dev4_inta = X86IntelMPIOIntAssignment(
            interrupt_type = 'INT',
            polarity = 'ConformPolarity',
            trigger = 'ConformTrigger',
            source_bus_id = 0,
            source_bus_irq = 0 + (4 << 2),
            dest_io_apic_id = io_apic.id,
            dest_io_apic_intin = 16)
    base_entries.append(pci_dev4_inta)
    def assignISAInt(irq, apicPin):
        assign_8259_to_apic = X86IntelMPIOIntAssignment(
                interrupt_type = 'ExtInt',
                polarity = 'ConformPolarity',
                trigger = 'ConformTrigger',
                source_bus_id = 1,
                source_bus_irq = irq,
                dest_io_apic_id = io_apic.id,
                dest_io_apic_intin = 0)
        base_entries.append(assign_8259_to_apic)
        assign_to_apic = X86IntelMPIOIntAssignment(
                interrupt_type = 'INT',
                polarity = 'ConformPolarity',
                trigger = 'ConformTrigger',
                source_bus_id = 1,
                source_bus_irq = irq,
                dest_io_apic_id = io_apic.id,
                dest_io_apic_intin = apicPin)
        base_entries.append(assign_to_apic)
    assignISAInt(0, 2)
    assignISAInt(1, 1)
    for i in range(3, 15):
        assignISAInt(i, i)
    workload.intel_mp_table.base_entries = base_entries
    workload.intel_mp_table.ext_entries = ext_entries

    return self

def makeLinuxX86System(mem_mode, numCPUs=1, mdesc=None, Ruby=False,
                       cmdline=None):
    # Build up the x86 system and then specialize it for Linux
    self = makeX86System(mem_mode, numCPUs, mdesc, X86FsLinux(), Ruby)

    # We assume below that there's at least 1MB of memory. We'll require 2
    # just to avoid corner cases.
    phys_mem_size = sum([r.size() for r in self.mem_ranges])
    assert(phys_mem_size >= 0x200000)
    assert(len(self.mem_ranges) <= 2)

    entries = \
       [
        # Mark the first megabyte of memory as reserved
        X86E820Entry(addr = 0, size = '639kB', range_type = 1),
        X86E820Entry(addr = 0x9fc00, size = '385kB', range_type = 2),
        # Mark the rest of physical memory as available
        X86E820Entry(addr = 0x100000,
                size = '%dB' % (self.mem_ranges[0].size() - 0x100000),
                range_type = 1),
        ]

    # Mark [mem_size, 3GB) as reserved if memory less than 3GB, which force
    # IO devices to be mapped to [0xC0000000, 0xFFFF0000). Requests to this
    # specific range can pass though bridge to iobus.
    if len(self.mem_ranges) == 1:
        entries.append(X86E820Entry(addr = self.mem_ranges[0].size(),
            size='%dB' % (0xC0000000 - self.mem_ranges[0].size()),
            range_type=2))

    # Reserve the last 16kB of the 32-bit address space for the m5op interface
    entries.append(X86E820Entry(addr=0xFFFF0000, size='64kB', range_type=2))

    # In case the physical memory is greater than 3GB, we split it into two
    # parts and add a separate e820 entry for the second part.  This entry
    # starts at 0x100000000,  which is the first address after the space
    # reserved for devices.
    if len(self.mem_ranges) == 2:
        entries.append(X86E820Entry(addr = 0x100000000,
            size = '%dB' % (self.mem_ranges[1].size()), range_type = 1))

    self.workload.e820_table.entries = entries

    # Command line
    if not cmdline:
        cmdline = 'earlyprintk=ttyS0 console=ttyS0 root=/dev/sda1 no_timer_check memory_corruption_check=0 random.trust_cpu=on init=/home/ubuntu/guestinit.sh'
    self.workload.command_line = fillInCmdline(mdesc, cmdline)
    return self

def cmd_line_template():
    if options.command_line and options.command_line_file:
        print("Error: --command-line and --command-line-file are "
              "mutually exclusive")
        sys.exit(1)
    if options.command_line:
        return options.command_line
    if options.command_line_file:
        return open(options.command_line_file).read().strip()
    return None

def build_system(np):
    cmdline = cmd_line_template()
    sys = makeLinuxX86System(test_mem_mode, np, bm[0], options.ruby,
                                  cmdline=cmdline)

    # Set the cache line size for the entire system
    sys.cache_line_size = options.cacheline_size

    # Create a top-level voltage domain
    sys.voltage_domain = VoltageDomain(voltage = options.sys_voltage)

    # Create a source clock for the system and set the clock period
    sys.clk_domain = SrcClockDomain(clock =  options.sys_clock,
            voltage_domain = sys.voltage_domain)

    # Create a CPU voltage domain
    sys.cpu_voltage_domain = VoltageDomain()

    # Create a source clock for the CPUs and set the clock period
    sys.cpu_clk_domain = SrcClockDomain(clock = options.cpu_clock,
                                             voltage_domain =
                                             sys.cpu_voltage_domain)

    if options.kernel is not None:
        sys.workload.object_file = binary(options.kernel)

    if options.script is not None:
        sys.readfile = options.script

    if options.lpae:
        sys.have_lpae = True

    if options.virtualisation:
        sys.have_virtualization = True

    sys.init_param = options.init_param

    # For now, assign all the CPUs to the same clock domain
    sys.cpu = [TestCPUClass(clk_domain=sys.cpu_clk_domain, cpu_id=i)
                    for i in range(np)]

    if ObjectList.is_kvm_cpu(TestCPUClass) or \
        ObjectList.is_kvm_cpu(FutureClass):
        sys.kvm_vm = KvmVM()

    if options.caches or options.l2cache:
        # By default the IOCache runs at the system clock
        sys.iocache = IOCache(addr_ranges = sys.mem_ranges)
        sys.iocache.cpu_side = sys.iobus.master
        sys.iocache.mem_side = sys.membus.slave
    elif not options.external_memory_system:
        sys.iobridge = Bridge(delay='50ns', ranges = sys.mem_ranges)
        sys.iobridge.slave = sys.iobus.master
        sys.iobridge.master = sys.membus.slave

    # Sanity check
    if options.simpoint_profile:
        if not ObjectList.is_noncaching_cpu(TestCPUClass):
            fatal("SimPoint generation should be done with atomic cpu")
        if np > 1:
            fatal("SimPoint generation not supported with more than one CPUs")

    for i in range(np):
        if options.simpoint_profile:
            sys.cpu[i].addSimPointProbe(options.simpoint_interval)
        if options.checker:
            sys.cpu[i].addCheckerCpu()
        if not ObjectList.is_kvm_cpu(TestCPUClass):
            if options.bp_type:
                bpClass = ObjectList.bp_list.get(options.bp_type)
                sys.cpu[i].branchPred = bpClass()
            if options.indirect_bp_type:
                IndirectBPClass = ObjectList.indirect_bp_list.get(
                    options.indirect_bp_type)
                sys.cpu[i].branchPred.indirectBranchPred = \
                    IndirectBPClass()
        sys.cpu[i].createThreads()

    # If elastic tracing is enabled when not restoring from checkpoint and
    # when not fast forwarding using the atomic cpu, then check that the
    # TestCPUClass is DerivO3CPU or inherits from DerivO3CPU. If the check
    # passes then attach the elastic trace probe.
    # If restoring from checkpoint or fast forwarding, the code that does this for
    # FutureCPUClass is in the Simulation module. If the check passes then the
    # elastic trace probe is attached to the switch CPUs.
    if options.elastic_trace_en and options.checkpoint_restore == None and \
        not options.fast_forward:
        CpuConfig.config_etrace(TestCPUClass, sys.cpu, options)

    CacheConfig.config_cache(options, sys)

    MemConfig.config_mem(options, sys)

    return sys

# Add options
parser = optparse.OptionParser()
Options.addCommonOptions(parser)
Options.addFSOptions(parser)

parser.add_option("--termport", action="store", type="int",
        default="3456", help="port for terminal to listen on")
parser.add_option("--cosim-pci", action="store", type="string",
        default="/tmp/cosim-pci", help="Cosim PCI Unix socket")
parser.add_option("--cosim-shm", action="store", type="string",
        default="/dev/shm/dummy_nic_shm", help="Cosim shared memory region")
parser.add_option("--cosim-sync", action="store_true",
        help="Synchronize with cosim pci device")

(options, args) = parser.parse_args()

if args:
    print("Error: script doesn't take any positional arguments")
    sys.exit(1)

# system under test can be any CPU
(TestCPUClass, test_mem_mode, FutureClass) = Simulation.setCPUClass(options)

# Match the memories with the CPUs, based on the options for the test system
TestMemClass = Simulation.setMemClass(options)

bm = [SysConfig(disks=options.disk_image, rootdev=options.root_device,
                mem=options.mem_size, os_type=options.os_type)]
np = options.num_cpus
sys = build_system(np)
root = Root(full_system=True, system=sys)

if options.timesync:
    root.time_sync_enable = True

if options.frame_capture:
    VncServer.frame_capture = True

Simulation.setWorkCountOptions(sys, options)
Simulation.run(options, root, sys, FutureClass)
