#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

#include "base/trace.hh"
#include "debug/SplitCPUAdapter.hh"
#include "mem/simbricks/split_cpu_adapter.hh"

namespace simbricks {
int id = 0;
static void sigint_handler(int dummy) {
  std::cout << "main_time = " << curTick() << std::endl;
  exit(0);
}

static void sigusr1_handler(int dummy) {
  std::cout << "main_time = " << curTick() << std::endl;
}

SplitCPUAdapter::SplitCPUAdapter(const Params *params)
    : SimObject(params),
      base::GenericBaseAdapter<SplitProtoM2C, SplitProtoC2M>::Interface(*this),
      adapter(*this, *this, params->sync),
      sync(params->sync),
      addrRanges(params->addr_ranges.begin(), params->addr_ranges.end()),
      cpu_side(params->name + ".cpu_side", this),
      int_req_proxy(params->name + ".int_req_proxy", this),
      int_resp_proxy(params->name + ".int_resp_proxy", this),
      pio_proxy(params->name + ".pio_proxy", this),
      mem_side(params->name + ".mem_side", this),
      reqCount(0) {
  DPRINTF(SplitCPUAdapter, "Hello from SplitCPUAdapter!\n");

  adapter.cfgSetPollInterval(params->poll_interval);
  if (params->listen) {
    adapter.listen(params->uxsocket_path, params->shm_path);
  } else {
    adapter.connect(params->uxsocket_path);
  }


  signal(SIGINT, sigint_handler);
  signal(SIGUSR1, sigusr1_handler);
  adapter.init();
}

SplitCPUAdapter::~SplitCPUAdapter()
{
}


Port &
SplitCPUAdapter::getPort(const std::string &if_name, PortID idx){
    panic_if(idx != InvalidPortID, "This object doesn't support vector ports");

    if (if_name == "cpu_side"){
        return cpu_side;
    }
    else if (if_name == "mem_side"){
        return mem_side;
    }
    else if (if_name == "int_req_proxy"){
        return int_req_proxy;
    }
    else if (if_name == "int_resp_proxy"){
        return int_resp_proxy;
    }
    else if (if_name == "pio_proxy"){
        return pio_proxy;
    }
    else{
        return SimObject::getPort(if_name, idx);
    }

}


AddrRangeList
SplitCPUAdapter::CPUSidePort::getAddrRanges() const{
    return owner->getAddrRanges();
}

void
SplitCPUAdapter::CPUSidePort::recvRespRetry(){

    DPRINTF(SplitCPUAdapter, "recvRespRetry\n");
}

AddrRangeList
SplitCPUAdapter::getAddrRanges() const{
    DPRINTF(SplitCPUAdapter, "Sending new ranges\n");

    if (mem_side.isConnected()){
        return mem_side.getAddrRanges();
    }
    else {
        return addrRanges;
    }
}

void
SplitCPUAdapter::sendRangeChange(){
    cpu_side.sendRangeChange();
}

bool
SplitCPUAdapter::handleRequest(PacketPtr pkt){

    DPRINTF(SplitCPUAdapter, "Got request for addr %#x, at %u\n",
        pkt->getAddr(), curTick());

    return true;
}


bool
SplitCPUAdapter::handleResponse(PacketPtr pkt){

    DPRINTF(SplitCPUAdapter, "Got response for addr %#x\n", pkt->getAddr());

    // forward to the other side port
    return true;
}



bool
SplitCPUAdapter::CPUSidePort::recvTimingReq(PacketPtr pkt){

    owner->reqCount++;
    pkt->req->_sbReqSeq = owner->reqCount;
    owner->in_flight.insert({owner->reqCount, pkt});

    DPRINTF(SplitCPUAdapter, "insert reqCount: %d requestorID: %d"
        " taskId: %u\n pktptr: %p ReqPtr: %p\n", \
        owner->reqCount, pkt->req->_masterId, \
        pkt->req->_taskId, pkt, pkt->req);

    volatile union SplitProtoC2M *msg = owner->c2mAlloc(false, false);
    uint8_t pkt_type = PACKET_TIMING;
    owner->PktToMsg(pkt, msg, pkt_type);

    // msg->dummy.own_type =  SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM;
    owner->adapter.outSend(msg, SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM);

    return true;

}


volatile union SplitProtoC2M*
SplitCPUAdapter::c2mAlloc(bool syncAlloc, bool functional){

    volatile union SplitProtoC2M *msg;
    uint64_t timestamp;
    
    timestamp = curTick();

    if (functional){ // if it's functional packet, send without latency
        timestamp -= params()->link_latency;
    }
    else{ // if it's not functional packet, send with latency
    }

    do {
        msg = (SplitProtoC2M*)SimbricksBaseIfOutAlloc(&adapter.baseIf, timestamp);
    } while (!msg);

    return msg;
}

AddrRangeList
SplitCPUAdapter::IntReqProxyPort::getAddrRanges() const{
    return owner->getAddrRanges();
}


void
SplitCPUAdapter::MemSidePort::recvRangeChange(){
    //todo send range change to memside
    AddrRangeList ranges = owner->mem_side.getAddrRanges();
    if (ranges.size() != 1){
        panic("more than one address range\n");
    }
    if (ranges.front().interleaved()){
        panic("not handling interleaved addr\n");
    }
    DPRINTF(SplitCPUAdapter, "MemSidePort receive range change\n"
    "%d: %s\n",
    ranges.size(), ranges.front().to_string());
    owner->sendRangeChange();
}

void
SplitCPUAdapter::IntRespProxyPort::recvRangeChange(){
    //todo send range change to memside
    AddrRangeList ranges = owner->int_resp_proxy.getAddrRanges();
    if (ranges.size() != 1){
        panic("more than one address range\n");
    }
    if (ranges.front().interleaved()){
        panic("not handling interleaved addr\n");
    }
    DPRINTF(SplitCPUAdapter, \
    "IntRespProxyPort receive range change\n%d: %s\n", \
    ranges.size(), ranges.front().to_string());

    volatile union SplitProtoC2M *msg = owner->c2mAlloc(false, true);
    volatile struct SplitGem5AddrRange *amsg = &msg->addr_range;
    AddrRange range = ranges.front();
    amsg->pkt_type = PACKET_ADDR_RANGE | PACKET_FUNCTIONAL | INT_RESP_PROXY;
    amsg->size = 1;
    amsg->_start[0] = range.start();
    amsg->_end[0] = range.end();

    // amsg->own_type = SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM;
    owner->adapter.outSend((volatile SplitProtoC2M*)amsg, SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM);

}

void
SplitCPUAdapter::PioProxyPort::recvRangeChange(){
    //todo send range change to memside
    AddrRangeList ranges = owner->pio_proxy.getAddrRanges();
    if (ranges.size() != 1){
        panic("more than one address range\n");
    }
    if (ranges.front().interleaved()){
        panic("not handling interleaved addr\n");
    }
    DPRINTF(SplitCPUAdapter, "PioProxyPort receive range change\n"
    "%d: %s\n",
    ranges.size(), ranges.front().to_string());

    volatile union SplitProtoC2M *msg = owner->c2mAlloc(false, true);
    volatile struct SplitGem5AddrRange *amsg = &msg->addr_range;
    AddrRange range = ranges.front();
    amsg->pkt_type = PACKET_ADDR_RANGE | PACKET_FUNCTIONAL | PIO_PROXY;
    amsg->size = 1;
    amsg->_start[0] = range.start();
    amsg->_end[0] = range.end();

    // amsg->own_type = SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM;
    owner->adapter.outSend((volatile SplitProtoC2M*)amsg, SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM);
}

void
SplitCPUAdapter::CPUSidePort::recvFunctional(PacketPtr pkt){
    return owner->handleFunctional(pkt);
}


size_t
SplitCPUAdapter::introOutPrepare(void *data, size_t maxlen)
{
    size_t introlen = sizeof(struct SimbricksProtoMemIntro);
    assert(introlen <= maxlen);
    memset(data, 0, introlen);
    return introlen;
}

void
SplitCPUAdapter::introInReceived(const void *data, size_t len)
{
    assert(len == sizeof(struct SimbricksProtoMemIntro));
}

void SplitCPUAdapter::handleInMsg(volatile SplitProtoM2C *msg) {
    uint8_t pkt_ty;

    pkt_ty = msg->dummy.own_type & SPLIT_PROTO_M2C_MSG_MASK;
    switch (pkt_ty) {
        case SPLIT_PROTO_M2C_SYNC:
          // sync message do nothing
          break;
        case SPLIT_PROTO_M2C_RECV:
          // DPRINTF(SplitCPUAdapter, "received a data packet\n");
          pkt_ty = msg->dummy.pkt_type;
          uint8_t size;
          // handle data packet (timing, functional, addr range)
          //  Address range list packet is only from INT_REQ_PROXY port
          if (pkt_ty ==
              (PACKET_ADDR_RANGE | PACKET_FUNCTIONAL | INT_REQ_PROXY)) {
            volatile struct SplitGem5AddrRange *amsg = &msg->addr_range;
            size = amsg->size;
            int i;
            for (i = 0; i < size; i++) {
              AddrRange range(amsg->_start[i], amsg->_end[i]);
              int_req_proxy.ranges_.push_back(range);
            }
            int_req_proxy.sendRangeChange();
          } else {
            // if (timing)
            volatile struct SplitGem5Packet *spkt = &msg->packet;
            // DPRINTF(SplitCPUAdapter, "receive cmd: %u\n",
            //(enum Command)spkt->cmd);
            if (((enum Command)spkt->cmd == ReadResp) |
                ((enum Command)spkt->cmd == ReadExResp) |
                ((enum Command)spkt->cmd == UpgradeResp)) {
              DPRINTF(SplitCPUAdapter, "received readResp\n");
              auto search = in_flight.find((uint32_t)spkt->req._reqCount);
              if (search != in_flight.end()) {
                // transfer Simbricks message to Gem5 packet

                PacketPtr pkt = search->second;
                MemCmd _cmd(spkt->cmd);
                pkt->cmd = _cmd;
                pkt->flags = spkt->flags;
                pkt->_isSecure = spkt->_isSecure;
                pkt->_qosValue = spkt->_qosValue;
                pkt->addr = spkt->addr;
                pkt->size = spkt->size;
                if (spkt->bytesValid != 0) {
                  panic("bytesValid copy not implemented\n");
                }

                pkt->headerDelay = spkt->headerDelay;
                pkt->snoopDelay = spkt->snoopDelay;
                pkt->payloadDelay = spkt->payloadDelay;
                if (spkt->size > 0) {
                  pkt->data = new uint8_t[spkt->size];
                  memcpy(pkt->data, (void *)spkt->data, spkt->size);
                }

                DPRINTF(SplitCPUAdapter,
                        "found and erase! taskId: %u pktptr: %p\n",
                        (uint32_t)spkt->req._taskId, search->second);

                in_flight.erase(search);

                DPRINTF(SplitCPUAdapter, "do mem timing response\n");
                if (!cpu_side.sendTimingResp(pkt)){
                    DPRINTF(SplitCPUAdapter, "sendTimingResp failed\n");
                }

              } else {
                DPRINTF(SplitCPUAdapter,
                        "no taskId found taskId: %u pktptr: %p\n",
                        (uint32_t)spkt->req._taskId, search->second);
                panic("not found taskId\n");
              }

            } else {
              panic("other type of packet no impl: %d\n",
                    (enum Command)spkt->cmd);
            }
          }

          break;
        default:
          panic("handleInMsg: unsupported type=%x", pkt_ty);
    }
    adapter.inDone(msg);
}

void SplitCPUAdapter::startup() {
  adapter.startup();
}

void SplitCPUAdapter::initIfParams(SimbricksBaseIfParams &p) {
  SimbricksBaseIfDefaultParams(&p);
  p.link_latency = params()->link_latency;
  p.sync_interval = params()->sync_tx_interval;
}

void
SplitCPUAdapter::init()
{
}


void
SplitCPUAdapter::handleFunctional(PacketPtr pkt){
    //DPRINTF(SplitCPUAdapter, "%s\n", pkt->print());
    volatile union SplitProtoC2M *msg = c2mAlloc(false, true);
    volatile struct SplitGem5Packet *spkt = &msg->packet;

    //print one packet
    if (id <= 10){
        DPRINTF(SplitCPUAdapter, "id: %d\n", id);
        int vsize = pkt->bytesValid.size();
        // DPRINTF(SplitCPUAdapter, "cmd: %s, id: %u, "
        // "data: %p, addr: %p\nsec: %u, size: %u, qos: %u"
        // " bytesValidSize: %d\n", \
        // pkt->cmd.toString().c_str(), pkt->id, (uint8_t *)pkt->data, \
        // pkt->getAddr(),pkt->isSecure(), \
        // pkt->getSize(), pkt->qosValue(), \
        // vsize);

        int k = 0;
        for (k = 0; k < pkt->getSize(); k += 8){
            DPRINTF(SplitCPUAdapter, "%2X%2X%2X%2X %2X%2X%2X%2X\n", \
            *((uint8_t *)pkt->data+k), *((uint8_t *)pkt->data+k+1), \
            *((uint8_t *)pkt->data+k+2), *((uint8_t *)pkt->data+k+3), \
            *((uint8_t *)pkt->data+k+4), *((uint8_t *)pkt->data+k+5), \
            *((uint8_t *)pkt->data+k+6), *((uint8_t *)pkt->data+k+7) \
            );
        }
    }
    id++;

    spkt->flags = (enum FlagsType)pkt->getFlag();
    spkt->cmd = (enum Command)pkt->cmd.toInt();
    spkt->packet_id = pkt->id;
    spkt->_isSecure = pkt->isSecure();
    spkt->_qosValue = pkt->qosValue();
    //copy original requset data
    spkt->req._paddr = pkt->req->_paddr;
    spkt->req._size = pkt->req->_size;
    int req_bvsize = pkt->req->_byteEnable.size();
    if (req_bvsize != 0){
        //panic("request bytesValid copy not implemented\n");
        //DPRINTF(SplitCPUAdapter, "req byteEnable size is %d\n", req_bvsize);
        int e;
        for (e = 0; e < req_bvsize; e++){
            if (pkt->req->_byteEnable[e]){
                spkt->req._byteEnable |= (0x1 << e);
            }
        }
    }else{
        spkt->req._byteEnable = 0;
    }
    /*
    This _masterId should be changed to _requestorId after upgrade
    */
    spkt->req._requestorId = pkt->req->_masterId;
    spkt->req._flags = pkt->req->_flags;
    
    /*
    This _masterId should be changed to _cacheCoherenceFlags after upgrade
    */
    spkt->req._cacheCoherenceFlags = pkt->req->_memSpaceConfigFlags;
    spkt->req.privateFlags = pkt->req->privateFlags;
    spkt->req._time = pkt->req->_time;
    spkt->req._taskId = pkt->req->_taskId;
    spkt->req._streamId = pkt->req->_streamId;
    spkt->req._vaddr = pkt->req->_vaddr;
    spkt->req._extraData = pkt->req->_extraData;
    spkt->req._contextId = pkt->req->_contextId;
    spkt->req._pc = pkt->req->_pc;
    spkt->req._reqInstSeqNum = pkt->req->_reqInstSeqNum;
    
    /*
    This _masterId should be uncommented after upgrade
    */    
    //spkt->req._instCount = pkt->req->_instCount;

    spkt->addr = pkt->getAddr();
    spkt->size = pkt->getSize();

    // copy byteValid bitmap if there is any,
    // since it seems not used for our case,
    // make it panic
    int bvsize = pkt->bytesValid.size();
    if (bvsize != 0){
        panic("bytesValid copy not implemented\n");
    }
    spkt->bytesValid = 0;
    //spkt->htmReturnReason = (enum HtmCacheFailure) pkt->htmReturnReason;
    spkt->headerDelay = pkt->headerDelay;
    spkt->snoopDelay = pkt->snoopDelay;
    spkt->payloadDelay = pkt->payloadDelay;
    spkt->pkt_type = PACKET_FUNCTIONAL;

    // copy request data if there is any
    if (pkt->getSize() != 0){

        memcpy((void*)spkt->data, pkt->data, pkt->getSize());
    }

    /********** DELETE THE ORIGINAL PACKET *****************/
    //delete pkt;

    // spkt->own_type = SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM;
    adapter.outSend((volatile SplitProtoC2M*)spkt, SPLIT_PROTO_C2M_RECV | SPLIT_PROTO_C2M_OWN_MEM);
}


void
SplitCPUAdapter::PktToMsg(PacketPtr pkt, volatile union SplitProtoC2M *msg,
                            uint8_t pkt_type){

    volatile struct SplitGem5Packet *spkt = &msg->packet;

    spkt->flags = (enum FlagsType)pkt->getFlag();
    spkt->cmd = (enum Command)pkt->cmd.toInt();
    spkt->packet_id = pkt->id;
    spkt->_isSecure = pkt->isSecure();
    spkt->_qosValue = pkt->qosValue();
    //copy original requset data
    spkt->req._paddr = pkt->req->_paddr;
    spkt->req._size = pkt->req->_size;
    int req_bvsize = pkt->req->_byteEnable.size();
    if (req_bvsize != 0){
        //panic("request bytesValid copy not implemented\n");
        //DPRINTF(SplitCPUAdapter, "req byteEnable size is %d\n", req_bvsize);
        int e;
        for (e = 0; e < req_bvsize; e++){
            if (pkt->req->_byteEnable[e]){
                spkt->req._byteEnable |= (0x1 << e);
            }
        }
    }else{
        spkt->req._byteEnable = 0;
    }
    
    /*
    This _masterId should be changed to _requestorId after upgrade
    */
    spkt->req._requestorId = pkt->req->_masterId;
    spkt->req._flags = pkt->req->_flags;
    
    /*
    This _masterId should be changed to _cacheCoherenceFlags after upgrade
    */
    spkt->req._cacheCoherenceFlags = pkt->req->_memSpaceConfigFlags;
    spkt->req.privateFlags = pkt->req->privateFlags;
    spkt->req._time = pkt->req->_time;
    spkt->req._taskId = pkt->req->_taskId;
    spkt->req._streamId = pkt->req->_streamId;
    spkt->req._vaddr = pkt->req->_vaddr;
    spkt->req._extraData = pkt->req->_extraData;
    
    spkt->req._contextId = pkt->req->_contextId;
    spkt->req._pc = pkt->req->_pc;
    spkt->req._reqInstSeqNum = pkt->req->_reqInstSeqNum;
    /*
    This _masterId should be uncommented after upgrade
    */    
    //spkt->req._instCount = pkt->req->_instCount;
    spkt->req._reqCount = reqCount;

    spkt->addr = pkt->getAddr();
    spkt->size = pkt->getSize();

    // copy byteValid bitmap if there is any,
    // since it seems not used for our case,
    // make it panic
    int bvsize = pkt->bytesValid.size();
    if (bvsize != 0){
        panic("bytesValid copy not implemented\n");
    }
    spkt->bytesValid = 0;
    //spkt->htmReturnReason = (enum HtmCacheFailure) pkt->htmReturnReason;
    spkt->headerDelay = pkt->headerDelay;
    spkt->snoopDelay = pkt->snoopDelay;
    spkt->payloadDelay = pkt->payloadDelay;
    spkt->pkt_type = pkt_type;

    // copy request data if there is any
    if ((pkt->getSize() != 0) && (pkt->data != NULL)){
        memcpy((void*)spkt->data, pkt->data, pkt->getSize());
    }
}


}  // namespace simbricks

simbricks::SplitCPUAdapter *
SplitCPUAdapterParams::create()
{
    return new simbricks::SplitCPUAdapter(this);
}
