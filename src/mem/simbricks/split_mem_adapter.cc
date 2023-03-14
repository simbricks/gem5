#include <chrono>
#include <csignal>
#include <iostream>
#include <thread>

#include "base/trace.hh"
#include "debug/SplitMEMAdapter.hh"
#include "mem/simbricks/split_mem_adapter.hh"

namespace simbricks{

static int id = 0;
static void sigint_handler(int dummy)
{
    std::cout << "main_time = " << curTick() << std::endl;
    exit(0);
}

static void sigusr1_handler(int dummy) {
  std::cout << "main_time = " << curTick() << std::endl;
}

SplitMEMAdapter::SplitMEMAdapter(const Params *params)
    : SimObject(params),
      base::GenericBaseAdapter<SplitProtoC2M, SplitProtoM2C>::Interface(*this),
      adapter(*this, *this, params->sync),
      sync(params->sync),
      mem_side(params->name + ".mem_side", this),
      int_resp_proxy(params->name + ".int_resp_proxy", this),
      int_req_proxy(params->name + ".int_req_proxy", this),
      pio_proxy(params->name + ".pio_proxy", this) {

    DPRINTF(SplitMEMAdapter, "hello from SplitMEMAdapter!\n");

    adapter.cfgSetPollInterval(params->poll_interval);
    if (params->listen) {
      adapter.listen(params->uxsocket_path, params->shm_path);
    } else {
      adapter.connect(params->uxsocket_path);
    }

    signal(SIGINT, sigint_handler);
    signal(SIGUSR1, sigusr1_handler);

}

SplitMEMAdapter::~SplitMEMAdapter()
{
}

void SplitMEMAdapter::startup() {
  adapter.startup();
}


size_t
SplitMEMAdapter::introOutPrepare(void *data, size_t maxlen)
{
    size_t introlen = sizeof(struct SimbricksProtoMemIntro);
    assert(introlen <= maxlen);
    memset(data, 0, introlen);
    return introlen;
}

void
SplitMEMAdapter::introInReceived(const void *data, size_t len)
{
    assert(len == sizeof(struct SimbricksProtoMemIntro));
}

Port &
SplitMEMAdapter::getPort(const std::string &if_name, PortID idx){
    panic_if(idx != InvalidPortID, "This object doesn't support vector ports");

    if (if_name == "mem_side"){
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

void SplitMEMAdapter::initIfParams(SimbricksBaseIfParams &p) {
  SimbricksBaseIfDefaultParams(&p);
  p.link_latency = params()->link_latency;
  p.sync_interval = params()->sync_tx_interval;
}

void
SplitMEMAdapter::init()
{
    adapter.init();
}

volatile union SplitProtoM2C *SplitMEMAdapter::m2cAlloc(bool syncAlloc,
                                                        bool functional) {
    volatile union SplitProtoM2C *msg;
    uint64_t timestamp;

    timestamp = curTick();


    if (functional){ // if it's functional packet, send without latency
        timestamp -= params()->link_latency;
    }
    else{ // if it's not functional packet, send with latency
    }

    do {
        msg = (SplitProtoM2C*)SimbricksBaseIfOutAlloc(&adapter.baseIf, timestamp);
    } while (!msg);


    return msg;
}


void
SplitMEMAdapter::IntReqProxyPort::recvRangeChange() {
    AddrRangeList ranges = getAddrRanges();
    int rsize = ranges.size();

    DPRINTF(SplitMEMAdapter, \
    "IntReqProxyPort receive range change\n%d\n", \
    ranges.size());

    if (rsize > 150){
        panic( \
        "IntReqProxyPort: more than 150 address ranges: %d\n", \
        ranges.size());
    }

    for (auto const& i : ranges){

        if (i.interleaved()){
            panic("not handling interleaved addr\n");
        }
        DPRINTF(SplitMEMAdapter, "addr range: %s\n", i.to_string());
    }

    volatile union SplitProtoM2C *msg = owner->m2cAlloc(false, true);
    volatile struct SplitGem5AddrRange *amsg = &msg->addr_range;

    //AddrRange range = ranges.front();
    amsg->pkt_type =  PACKET_ADDR_RANGE | PACKET_FUNCTIONAL | INT_REQ_PROXY;
    amsg->size = rsize;

    int k = 0;
    for (auto const& i : ranges){
        amsg->_start[k] = i.start();
        amsg->_end[k] = i.end();
        k++;
    }

    owner->adapter.outSend((volatile SplitProtoM2C*)amsg, SPLIT_PROTO_M2C_RECV | SPLIT_PROTO_M2C_OWN_CPU);

}


AddrRangeList
SplitMEMAdapter::PioProxyPort::getAddrRanges() const{
    //return owner->getAddrRanges();
    return ranges_;
}
AddrRangeList
SplitMEMAdapter::IntRespProxyPort::getAddrRanges() const{
    //return owner->getAddrRanges();
    return ranges_;
}

AddrRangeList
SplitMEMAdapter::getAddrRanges() const{
    DPRINTF(SplitMEMAdapter, "getAddrRanges\n");
    return mem_side.getAddrRanges();
    // todo
}

void
SplitMEMAdapter::handleFunctional(PacketPtr pkt){
    DPRINTF(SplitMEMAdapter, "handlefunctional\n");
}

void
SplitMEMAdapter::sendRangeChange(){
    DPRINTF(SplitMEMAdapter, "sending range change\n");
}

bool
SplitMEMAdapter::MEMSidePort::recvTimingResp(PacketPtr pkt){
    return owner->handleResponse(pkt);
}

void
SplitMEMAdapter::MEMSidePort::recvRangeChange(){
    //todo: send cpu side range change
    DPRINTF(SplitMEMAdapter, "MEMSidePort received range change\n");
}

void
SplitMEMAdapter::MEMSidePort::recvReqRetry(){
    DPRINTF(SplitMEMAdapter, "MEMSidePort received reqRetry\n");
    if (blockedPkt.empty()){
        panic("retry is empty\n");
    }
    else{
        PacketPtr pkt = blockedPkt.front();
        blockedPkt.erase(blockedPkt.begin());
        if ( !sendTimingReq(pkt)){
            blockedPkt.push_back(pkt);
            DPRINTF(SplitMEMAdapter, "MEMSidePort failed retry again\n");
        }
    }
}



void
SplitMEMAdapter::PktToMsg(PacketPtr pkt, volatile union SplitProtoM2C *msg,
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
    spkt->req._reqCount = pkt->req->_sbReqSeq;

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
    if (pkt->getSize() != 0){

        memcpy((void*)spkt->data, pkt->data, pkt->getSize());
    }
}


bool
SplitMEMAdapter::handleResponse(PacketPtr pkt){
    DPRINTF(SplitMEMAdapter, "Got response for addr %#x\n", pkt->getAddr());

////////////// print packet /////////////////////
    // int vsize = pkt->bytesValid.size();
    // DPRINTF(SplitMEMAdapter, "cmd: %s, id: %u, "
    // "data: %p, addr: %p\nsec: %u, size: %u, qos: %u"
    // " bytesValidSize: %d\n", \
    // pkt->cmd.toString().c_str(), pkt->id, (uint8_t *)pkt->data, \
    // pkt->getAddr(),pkt->isSecure(), \
    // pkt->getSize(), pkt->qosValue(), \
    // vsize);

    //DPRINTF(SplitMEMAdapter, "reqptr: %p reqTaskId: %u cmdInt: %u\n",
    //pkt->req,
    //pkt->req->_taskId, (enum Command)pkt->cmd.toInt());

    int k = 0;
    for (k = 0; k < pkt->getSize(); k += 8){
        DPRINTF(SplitMEMAdapter, "%2X%2X%2X%2X %2X%2X%2X%2X\n", \
        *((uint8_t *)pkt->data+k), *((uint8_t *)pkt->data+k+1), \
        *((uint8_t *)pkt->data+k+2), *((uint8_t *)pkt->data+k+3), \
        *((uint8_t *)pkt->data+k+4), *((uint8_t *)pkt->data+k+5), \
        *((uint8_t *)pkt->data+k+6), *((uint8_t *)pkt->data+k+7) \
        );
    }
/////////////////////////////////////////////////////

    volatile union SplitProtoM2C *msg = m2cAlloc(false, false);
    PktToMsg(pkt, msg, PACKET_TIMING);
    adapter.outSend((volatile union SplitProtoM2C*)msg, (SPLIT_PROTO_M2C_RECV | SPLIT_PROTO_M2C_OWN_CPU));

    return true;
}

void
SplitMEMAdapter::handleInMsg(volatile SplitProtoC2M *msg){

    uint8_t ty;
    ty = msg->dummy.own_type & SPLIT_PROTO_C2M_MSG_MASK;

    switch(ty){
        case SPLIT_PROTO_C2M_SYNC:
            DPRINTF(SplitMEMAdapter, \
                "received sync from CPU Side ts: %lu\n", \
                adapter.baseIf.in_timestamp);
            break;
        case SPLIT_PROTO_C2M_RECV:
            if (msg->dummy.pkt_type & PACKET_ADDR_RANGE){
                // The message is a address range packet
                volatile struct SplitGem5AddrRange *amsg = &msg->addr_range;
                if (amsg->size != 1){
                    panic("not handling addr range size larger than one\n");
                }
                AddrRange range(amsg->_start[0], amsg->_end[0]);

                if (amsg->pkt_type & PIO_PROXY){
                    // Address range packet from cpu side PIO proxy
                    DPRINTF(SplitMEMAdapter, \
                    "received a PIO address range packet\n");
                    pio_proxy.ranges_.push_back(range);
                    pio_proxy.sendRangeChange();
                }
                else if (amsg->pkt_type & INT_RESP_PROXY){
                    // Address range change packet from INT_RESP proxy
                    DPRINTF(SplitMEMAdapter, \
                    "received a INT_RESP address range packet\n");
                    int_resp_proxy.ranges_.push_back(range);
                    int_resp_proxy.sendRangeChange();
                }


            }
            else{ // The message is a gem5 packet

                volatile struct SplitGem5Packet *spkt = &msg->packet;
                // Do packet transfer

                id++;
                //DPRINTF(SplitMEMAdapter, "got %d th msg from the Q\n", id);
                //print first 10 packets
                if (id <= 10){

                }

                RequestPtr req = std::make_shared<Request>();
                req->_paddr = spkt->req._paddr;
                req->_size = spkt->req._size;
                int e;
                for (e = 0; e < sizeof(uint64_t)*8; e++){
                    uint64_t m = 0x1 << e;
                    if (spkt->req._byteEnable & m){
                        req->_byteEnable.push_back(true);
                    }
                }

                // the original requestor ID exceeds memside max requestor
                // set requestor ID to 1

                //req->_requestorId = spkt->req._requestorId;

                /*
                This _masterId should be changed to _requestorId after upgrade
                */
                req->_masterId = 1;

                req->_flags = spkt->req._flags;
                /*
                This _masterId should be changed to _cacheCoherenceFlags after upgrade
                */
                req->_memSpaceConfigFlags = spkt->req._cacheCoherenceFlags;
                req->privateFlags = spkt->req.privateFlags;
                req->_time = spkt->req._time;
                req->_taskId = spkt->req._taskId;
                req->_streamId = spkt->req._streamId;
                req->_vaddr = spkt->req._streamId;
                req->_extraData = spkt->req._extraData;
                req->_contextId = spkt->req._contextId;
                req->_pc = spkt->req._pc;
                req->_reqInstSeqNum = spkt->req._reqInstSeqNum;

                /*
                This _masterId should be uncommented after upgrade
                */    
                //req->_instCount = spkt->req._instCount;
                req->_sbReqSeq = spkt->req._reqCount;
                MemCmd _cmd(spkt->cmd);
                PacketPtr pkt = new Packet(req, _cmd);
                pkt->flags = spkt->flags;
                pkt->_isSecure = spkt->_isSecure;
                pkt->_qosValue = spkt->_qosValue;
                pkt->addr = spkt->addr;
                pkt->size = spkt->size;
                if (spkt->bytesValid != 0){
                    panic("bytesValid copy not implemented\n");
                }

                pkt->headerDelay = spkt->headerDelay;
                pkt->snoopDelay = spkt->snoopDelay;
                pkt->payloadDelay = spkt->payloadDelay;
                if (spkt->size > 0){
                    pkt->data = new uint8_t[spkt->size];
                    memcpy(pkt->data, (void*)spkt->data, spkt->size);
                }

                if (spkt->pkt_type == PACKET_FUNCTIONAL){
                    //if it is functional packet, call handle fucntional
                    mem_side.sendFunctional(pkt);
                }
                else if (spkt->pkt_type & PACKET_TIMING){
                    DPRINTF(SplitMEMAdapter, "do mem timing req\n");

                    DPRINTF(SplitMEMAdapter, \
                        "reqptr: %p reqTaskId: %u cmdInt:%u %s\n", \
                        pkt->req, pkt->req->_taskId, \
                        (enum Command)pkt->cmd.toInt(), \
                        pkt->cmd.toString().c_str());

                    if (!mem_side.sendTimingReq(pkt)){
                        //failed to send timing, retry later
                        mem_side.blockedPkt.push_back(pkt);
                    }
                }
                else{
                    panic("unknown packet type: %x\n", spkt->pkt_type);
                }
            }
            break;
        default:
            panic("pollQueues: unsupported type=%x\n", ty);
    }
    adapter.inDone(msg);

}


} // namespace simbricks

simbricks::SplitMEMAdapter *
SplitMEMAdapterParams::create()
{
    return new simbricks::SplitMEMAdapter(this);
}
