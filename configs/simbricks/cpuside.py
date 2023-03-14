
from __future__ import print_function
from __future__ import absolute_import

import optparse
import sys
import os

import m5
from m5.defines import buildEnv
from m5.objects import *
from m5.params import NULL
from m5.util import addToPath, fatal, warn


# Add the common scripts to our path
m5.util.addToPath('../')
# import the caches which we made
from common.Caches import *
from common import Options
from common import MemConfig
from common import ObjectList

def malformedSplitSimUrl(s):
    print("Error: SplitSim URL", s, "is malformed")
    sys.exit(1)

# Parse SplitSim "URLs" in the following format:
# ADDR[ARGS]
# ADDR = connect:UX_SOCKET_PATH |
#        listen:UX_SOCKET_PATH:SHM_PATH
# ARGS = :sync | :link_latency=XX | :sync_interval=XX
def parseSplitSimUrl(s):
    out = {'sync': False}
    parts = s.split(':')
    if len(parts) < 2:
        malformedSplitSimUrl(s)

    if parts[0] == 'connect':
        out['listen'] = False
        out['uxsocket_path'] = parts[1]
        parts = parts[2:]
    elif parts[0] == 'listen':
        if len(parts) < 3:
            malformedSplitSimUrl(s)
        out['listen'] = True
        out['uxsocket_path'] = parts[1]
        out['shm_path'] = parts[2]
        parts = parts[3:]
    else:
        malformedSplitSimUrl(s)

    for p in parts:
        if p == 'sync':
            out['sync'] = True
        elif p.startswith('sync_interval='):
            out['sync_tx_interval'] = p.split('=')[1]
        elif p.startswith('latency='):
            out['link_latency'] = p.split('=')[1]
        else:
            malformedSplitSimUrl(s)
    return out

def create_mem_ctrl(cls, r, i, nbr_mem_ctrls, intlv_bits, intlv_size):

    import math
    intlv_low_bit = int(math.log(intlv_size, 2))
    xor_low_bit = 20
    ctrl = cls()
    ctrl.range = m5.objects.AddrRange(r.start, size = r.size(),
                                      intlvHighBit = \
                                          intlv_low_bit + intlv_bits - 1,
                                      xorHighBit = \
                                          xor_low_bit + intlv_bits - 1,
                                      intlvBits = intlv_bits,
                                      intlvMatch = i)
    return ctrl


def configMem(options, system):

    # Mandatory options
    opt_mem_type = options.mem_type
    opt_mem_channels = options.mem_channels

    # Optional options
    opt_tlm_memory = getattr(options, "tlm_memory", None)
    opt_external_memory_system = getattr(options, "external_memory_system",
                                         None)
    opt_elastic_trace_en = getattr(options, "elastic_trace_en", False)
    opt_mem_ranks = getattr(options, "mem_ranks", None)
    opt_dram_powerdown = getattr(options, "enable_dram_powerdown", None)
    opt_mem_channels_intlv = getattr(options, "mem_channels_intlv", 128)

    nbr_mem_ctrls = opt_mem_channels
    import math
    from m5.util import fatal
    intlv_bits = int(math.log(nbr_mem_ctrls, 2))
    if 2 ** intlv_bits != nbr_mem_ctrls:
        fatal("Number of memory channels must be a power of 2")
    cls = ObjectList.mem_list.get(opt_mem_type)
    mem_ctrls = []

    intlv_size = max(opt_mem_channels_intlv, system.cache_line_size.value)
    for r in system.mem_ranges:
        for i in range(nbr_mem_ctrls):
            mem_ctrl = create_mem_ctrl(cls, r, i, nbr_mem_ctrls, intlv_bits,
                                       intlv_size)
            # Set the number of ranks based on the command-line
            # options if it was explicitly set
            if issubclass(cls, m5.objects.DRAMCtrl) and opt_mem_ranks:
                mem_ctrl.ranks_per_channel = opt_mem_ranks

            mem_ctrls.append(mem_ctrl)

    system.mem_ctrls = mem_ctrls

    for i in range(len(system.mem_ctrls)):
        system.mem_ctrls[i].port = system.splitcpu_adapter.mem_side


parser = optparse.OptionParser()
Options.addCommonOptions(parser)
Options.addSEOptions(parser)

parser.add_option("--splitsim", action="append", type="string",
        default=[], help="SplitSim URLs to connect to")
parser.add_option("--split-cpu", type=int, default=0)
parser.add_option("--split-numa", type=int, default=0)

(options, args) = parser.parse_args()
if args:
    print("Error: script doesn't take any positional arguments")
    sys.exit(1)

system = System()
system.clk_domain = SrcClockDomain()
system.clk_domain.clock = '1GHz'
system.clk_domain.voltage_domain = VoltageDomain()
system.mem_mode = 'timing'
#system.mem_ranges = [AddrRange('1GB')]

idv_mem_start = f'{options.split_cpu}GB'
idv_mem_end = f'{options.split_cpu + 1}GB'
system.mem_ranges = [AddrRange(idv_mem_start, idv_mem_end)]


system.cpu = TimingSimpleCPU(cpu_id=options.split_cpu)

# Create L1 instruction and data cache
system.cpu.icache = L1_ICache(size = '32kB')
system.cpu.dcache = L1_DCache(size = '32kB')

# Connect cpu to L1 caches
system.cpu.icache_port = system.cpu.icache.cpu_side
system.cpu.dcache_port = system.cpu.dcache.cpu_side

# create L2 bus and connect
system.l2bus = L2XBar()
system.cpu.icache.mem_side = system.l2bus.slave
system.cpu.dcache.mem_side = system.l2bus.slave

# Create SimbricksAdapter object and Connect to L2 bus
params = parseSplitSimUrl(options.splitsim[0])
params['uxsocket_path'] = params['uxsocket_path'] + f'.{options.split_cpu}'
if (params['listen'] == True ):
    params['shm_path'] = params['shm_path'] + f'.{options.split_cpu}'
system.splitcpu_adapter = SplitCPUAdapter(**params)

# Create L2 cache and connect to L2 bus
system.l2 = L2Cache(size = '32MB')
system.l2.cpu_side = system.l2bus.master
system.l2.mem_side = system.splitcpu_adapter.cpu_side


# create the interrupt controller for the CPU
system.cpu.createInterruptController()

# Create Mem controller and connect to memory bus
# system.mem_ctrl = DRAMCtrl()
# system.mem_ctrl.dram = DDR3_1600_8x8()
# system.mem_ctrl.dram.range = system.mem_ranges[0]
# system.mem_ctrl.port = system.splitcpu_adapter.mem_side
configMem(options, system)


# For x86 only, make sure the interrupts are connected to the memory
# Note: these are directly connected to the memory bus and are not cached

# if m5.defines.buildEnv['TARGET_ISA'] == "x86":
system.cpu.interrupts[0].pio = system.splitcpu_adapter.pio_proxy
system.cpu.interrupts[0].int_master = system.splitcpu_adapter.int_req_proxy
system.cpu.interrupts[0].int_slave = system.splitcpu_adapter.int_resp_proxy

# Connect the system up to the membus
system.system_port = system.l2bus.slave



# system.workload = SEWorkload.init_compatible(
#     '/tests/test-progs/hello/bin/x86/linux/hello64-static')

# system.workload = SEWorkload.init_compatible(
#     'tests/test-progs/blackScholes/bin/bs64-static')

# system.workload = SEWorkload.init_compatible(
#     'tests/test-progs/membound/bin/mb64-static')

#phymem = 5242880 *  args.simbricks_cpu

process = Process(pid = 100 + options.split_cpu)
process.executable = '/OS/endhost-networking/work/sim/hejing/simbricks/sims/external/gem5/tests/test-progs/blackScholes/bin/bs64-static'
# process.cmd = ['tests/test-progs/hello/bin/x86/linux/hello64-static']
if options.cmd == "cpu":
    process.cmd = ['/tests/test-progs/blackScholes/bin/bs64-static', \
        '100', '1', '2', '3', '4', '300000', f'{options.split_cpu}']
elif options.cmd == "mem":
    process.cmd = ['/tests/test-progs/membound/bin/mb64-static', \
        '50000', '1500']

system.cpu.workload = [process]

system.cpu.createThreads()


root = Root(full_system = False, system = system)
m5.instantiate()
#system.cpu.workload[0].map(0, phymem, 5000000, True)

print("Beginning Simulation!\n")
exit_event = m5.simulate()
print('Exiting @ tick %i because %s\n' % (m5.curTick(), exit_event.getCause()))

