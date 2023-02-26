from m5.defines import buildEnv
from m5.params import *
from m5.proxy import *
from m5.SimObject import SimObject

class SplitCPUAdapter(SimObject):
    type = 'SplitCPUAdapter'
    cxx_header = "mem/simbricks/split_cpu_adapter.hh"
    cxx_class = 'simbricks::SplitCPUAdapter'

    cpu_side = SlavePort("CPU side port, receives requets")
    mem_side = MasterPort("Memory side port, receives responses")

    pio_proxy = MasterPort("bridges pio packets between CPU and memory bus")
    int_resp_proxy = MasterPort("bridges interrupt response packets \
        between CPU and memory bus")
    int_req_proxy = SlavePort("bridges interrupt request packets \
        between CPU and memory bus")
    addr_ranges = VectorParam.AddrRange([AllMemory],
         "Address range for the CPU-side port (to allow striping)")


    listen = Param.Bool(False, "Open listening instead of connecting")
    uxsocket_path = Param.String("unix socket path")
    shm_path = Param.String('/tmp/splitsim/', "Shared memory path")
    sync = Param.Bool(True, "Synchronized CPUAdapter")
    poll_interval = Param.Latency('100us', "poll interval size (unsync only)")
    sync_tx_interval = Param.Latency('500ns', "interval between syncs")
    link_latency = Param.Latency('10ns', "Latency for forwarding request/response")


class SplitMEMAdapter(SimObject):
    type = 'SplitMEMAdapter'
    cxx_header = "mem/simbricks/split_mem_adapter.hh"
    cxx_class = 'simbricks::SplitMEMAdapter'

    mem_side = MasterPort("Memory side port, receives responbes")
    latency = Param.Latency('10ns', "Latency for forwarding request/response")

    pio_proxy = SlavePort("bridges pio packets between CPU and memory bus")
    int_resp_proxy = SlavePort("bridges interrupt response packets \
        between CPU and memory bus")
    int_req_proxy = MasterPort("bridges interrupt request packets \
        between CPU and memory bus")

    listen = Param.Bool(False, "Open listening instead of connecting")
    uxsocket_path = Param.String("unix socket path")
    shm_path = Param.String('/tmp/splitsim/',"Shared memory path")
    sync = Param.Bool(True, "synchronized or not")
    poll_interval = Param.Latency('100us', "poll interval size (unsync only)")
    sync_tx_interval = Param.Latency('500ns', "interval between syncs")
    link_latency = Param.Latency('10ns', "Latency for forwarding request/response")
