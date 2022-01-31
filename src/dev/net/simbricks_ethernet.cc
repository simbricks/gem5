/*
 * Copyright (c) 2015 ARM Limited
 * All rights reserved
 *
 * The license below extends only to copyright in the software and shall
 * not be construed as granting a license to any other intellectual
 * property including but not limited to intellectual property relating
 * to a hardware implementation of the functionality of the software
 * licensed hereunder.  You may use the software subject to the license
 * terms below provided that you ensure that this notice is replicated
 * unmodified and in its entirety in all distributions of the software,
 * modified or unmodified, in source code or in binary form.
 *
 * Copyright (c) 2002-2005 The Regents of The University of Michigan
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer;
 * redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution;
 * neither the name of the copyright holders nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/* @file
 * Device module for modelling a fixed bandwidth full duplex ethernet link
 */

#include "dev/net/simbricks_ethernet.hh"

#include <fcntl.h>
#include <poll.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <cassert>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <iostream>
#include <string>
#include <vector>

#include "base/logging.hh"
#include "base/random.hh"
#include "base/trace.hh"
#include "debug/Ethernet.hh"
#include "debug/EthernetData.hh"
#include "debug/SimbricksEthernet.hh"
#include "dev/net/etherdump.hh"
#include "dev/net/etherint.hh"
#include "dev/net/etherpkt.hh"
#include "params/EtherLink.hh"
#include "sim/serialize.hh"
#include "sim/system.hh"

#define D2H_ELEN (9024 + 64)
#define D2H_ENUM 1024

#define H2D_ELEN (9024 + 64)
#define H2D_ENUM 1024

#define D2N_ELEN (9024 + 64)
#define D2N_ENUM 8192

#define N2D_ELEN (9024 + 64)
#define N2D_ENUM 8192


//namespace Simbricks{
namespace gem5
{


void sigusr1_handler(int dummy)
{
    std::cout << "main_time = " << curTick() << std::endl;
}

SimbricksEtherLink::SimbricksEtherLink(const Params *p)
    :SimObject(p),
    eth_delay(p->eth_delay),
    pollInterval(p->poll_interval), syncTxInterval(p->sync_tx_interval),
    sync(p->sync), sync_mode(p->sync_mode),
    pollEvent([this]{processPollEvent();}, name()),
    syncTxEvent([this]{processSyncTxEvent();}, name()),
    ReTxEvent([this]{ retransmit(); }, "SimbricksEthernet retransmit")

{
    Iface = new Interface(name() + ".int0", this);


    memset(&nicif_, 0, sizeof(nicif_));


    params.pci_socket_path = nullptr;
    params.eth_socket_path = p->uxsocket_path.c_str();
    params.shm_path = p->shm_path.c_str();

    params.pci_latency = 0;
    params.eth_latency = eth_delay;
    params.sync_delay = syncTxInterval;

    params.sync_pci = 0;
    params.sync_eth = sync;
    params.sync_mode = sync_mode;

    if (SimbricksNicIfInit(&nicif_, &params, &di) != 0) {
        panic("simbricks-etherlink: failed to initialize \
        simbricks connection");
    }

    DPRINTF(SimbricksEthernet, "NicIfInit suc\n");

}

void
SimbricksEtherLink::init(){
    //sighandler
    signal(SIGUSR1, sigusr1_handler);
}

SimbricksEtherLink::Interface::Interface(const std::string &name,\
 SimbricksEtherLink *tx)
    : EtherInt(name), txlink(tx)
{
    //tx->setTxInt(this);

}

SimbricksEtherLink::~SimbricksEtherLink()
{

}

bool
SimbricksEtherLink::recvSimulated(EthPacketPtr packet){
    //send to real
    volatile union SimbricksProtoNetD2N *msg_to =
        SimbricksNicIfD2NAlloc(&nicif_, curTick());

    if (!msg_to)
        return false;

    volatile struct SimbricksProtoNetD2NSend *rx;
    rx = &msg_to->send;
    rx->len = packet->length;
    //rx->port = 0;
    memcpy((void *)rx->data, packet->data, packet->length);

    // WMB();
    rx->own_type =
        SIMBRICKS_PROTO_NET_D2N_MSG_SEND | SIMBRICKS_PROTO_NET_D2N_OWN_NET;

    Iface->recvDone();
    return true;
}



int
SimbricksEtherLink::shm_create(const char *path, size_t size, void **addr) {
    int fd;
    void *p;

#ifdef SHM_ROUND_UP
    if (size % SHM_ROUND_UP != 0)
        size += SHM_ROUND_UP - (size % SHM_ROUND_UP);
#endif

    if ((fd = open(path, O_CREAT | O_RDWR, 0666)) == -1) {
        perror("util_create_shmsiszed: open failed");
        goto error_out;
    }
    if (ftruncate(fd, size) != 0) {
        perror("util_create_shmsiszed: ftruncate failed");
        goto error_remove;
    }

    if ((p = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED \
                    | MAP_POPULATE, fd, 0)) == (void *)-1) {
        perror("util_create_shmsiszed: mmap failed");
        goto error_remove;
    }

    memset(p, 0, size);

    *addr = p;
    return fd;

    error_remove:
    close(fd);
    unlink(path);
    error_out:
    return -1;
}


int
SimbricksEtherLink::uxsocket_init(const char *path) {
    int fd;
    struct sockaddr_un saun;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("uxsocket_init: socket failed");
        goto error_exit;
    }

    memset(&saun, 0, sizeof(saun));
    saun.sun_family = AF_UNIX;
    memcpy(saun.sun_path, path, strlen(path));
    if (bind(fd, (struct sockaddr *)&saun, sizeof(saun))) {
        perror("uxsocket_init: bind failed");
        goto error_close;
    }

    if (listen(fd, 5)) {
        perror("uxsocket_init: listen failed");
        goto error_close;
    }

    return fd;

    error_close:
    close(fd);
    error_exit:
    return -1;
}


int
SimbricksEtherLink::uxsocket_send(int connfd, void *data, size_t len, int fd) {
    ssize_t tx;
    struct iovec iov =
    {
        .iov_base = data,
        .iov_len = len,
    };
    union
    {
        char buf[CMSG_SPACE(sizeof(int))];
        struct cmsghdr align;
    } u;
    struct msghdr msg =
    {
        .msg_name = NULL,
        .msg_namelen = 0,
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = u.buf,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    struct cmsghdr *cmsg = &u.align;

    if (fd >= 0) {
        msg.msg_controllen = sizeof(u.buf);

        cmsg->cmsg_level = SOL_SOCKET;
        cmsg->cmsg_type = SCM_RIGHTS;
        cmsg->cmsg_len = CMSG_LEN(sizeof(int));

        *(int *)CMSG_DATA(cmsg) = fd;
    }

    if ((tx = sendmsg(connfd, &msg, 0)) != (ssize_t)len) {
        fprintf(stderr, "tx == %zd\n", tx);
        return -1;
    }

    return 0;
}


int
SimbricksEtherLink::accept_pci(struct SimbricksNicIf *nicif,
                      struct SimbricksProtoPcieDevIntro *di,
                      int pci_lfd,
                      int *sync_pci) {
    if ((nicif->pci_cfd = accept(pci_lfd, NULL, NULL)) < 0) {
        return -1;
    }
    close(pci_lfd);
    printf("pci connection accepted\n");

    di->d2h_offset = nicif->d2h_off;
    di->d2h_elen = D2H_ELEN;
    di->d2h_nentries = D2H_ENUM;

    di->h2d_offset = nicif->h2d_off;
    di->h2d_elen = H2D_ELEN;
    di->h2d_nentries = H2D_ENUM;

    if (*sync_pci)
        di->flags |= SIMBRICKS_PROTO_PCIE_FLAGS_DI_SYNC;
    else
        di->flags &= ~((uint64_t)SIMBRICKS_PROTO_PCIE_FLAGS_DI_SYNC);

    if (uxsocket_send(nicif->pci_cfd, di, sizeof(*di), nicif->shm_fd)) {
        return -1;
    }
    printf("pci intro sent\n");
    return 0;
}

int
SimbricksEtherLink::accept_eth(struct SimbricksNicIf *nicif,
                      int eth_lfd,
                      int *sync_eth) {
    struct SimbricksProtoNetDevIntro di;

    if ((nicif->eth_cfd = accept(eth_lfd, NULL, NULL)) < 0) {
        return -1;
    }
    close(eth_lfd);
    printf("eth connection accepted\n");

    memset(&di, 0, sizeof(di));
    di.flags = 0;
    if (*sync_eth)
        di.flags |= SIMBRICKS_PROTO_NET_FLAGS_DI_SYNC;

    di.d2n_offset = nicif->d2n_off;
    di.d2n_elen = D2N_ELEN;
    di.d2n_nentries = D2N_ENUM;

    di.n2d_offset = nicif->n2d_off;
    di.n2d_elen = N2D_ELEN;
    di.n2d_nentries = N2D_ENUM;

    if (uxsocket_send(nicif->eth_cfd, &di, sizeof(di), nicif->shm_fd)) {
        return -1;
    }
    printf("eth intro sent\n");
    return 0;
}

int
SimbricksEtherLink::accept_conns(struct SimbricksNicIf *nicif,
                        struct SimbricksProtoPcieDevIntro *di, int pci_lfd,
                        int *sync_pci, int eth_lfd, int *sync_eth) {
    struct pollfd pfds[2];
    int await_pci = pci_lfd != -1;
    int await_eth = eth_lfd != -1;
    int ret;

    while (await_pci || await_eth) {
        if (await_pci && await_eth) {
        // we're waiting on both fds
        pfds[0].fd = pci_lfd;
        pfds[1].fd = eth_lfd;
        pfds[0].events = pfds[1].events = POLLIN;
        pfds[0].revents = pfds[1].revents = 0;

        ret = poll(pfds, 2, -1);
        if (ret < 0) {
            perror("poll failed");
            return -1;
        }

        if (pfds[0].revents) {
            if (accept_pci(nicif, di, pci_lfd, sync_pci) != 0)
            return -1;
            await_pci = 0;
        }
        if (pfds[1].revents) {
            if (accept_eth(nicif, eth_lfd, sync_eth) != 0)
            return -1;
            await_eth = 0;
        }
        } else if (await_pci) {
        // waiting just on pci
        if (accept_pci(nicif, di, pci_lfd, sync_pci) != 0)
            return -1;
        await_pci = 0;
        } else {
        // waiting just on ethernet
        if (accept_eth(nicif, eth_lfd, sync_eth) != 0)
            return -1;
        await_eth = 0;
        }
    }

    return 0;
}

int
SimbricksEtherLink::SimbricksNicIfInit(\
                        struct SimbricksNicIf *nicif,
                       struct SimbricksNicIfParams *params,
                       struct SimbricksProtoPcieDevIntro *di)
                       {
  int pci_lfd = -1, eth_lfd = -1;


  // initialize nicif struct
  memset(nicif, 0, sizeof(*nicif));
  nicif->params = *params;
  nicif->pci_cfd = nicif->eth_cfd = -1;

  // ready in memory queues
  shm_size = (uint64_t)D2H_ELEN * D2H_ENUM + (uint64_t)H2D_ELEN * H2D_ENUM +
             (uint64_t)D2N_ELEN * D2N_ENUM + (uint64_t)N2D_ELEN * N2D_ENUM;
  if ((nicif->shm_fd = shm_create(params->shm_path, shm_size, &shmptr)) < 0) {
    return -1;
  }

  nicif->d2h_off = 0;
  nicif->h2d_off = nicif->d2h_off + (uint64_t)D2H_ELEN * D2H_ENUM;
  nicif->d2n_off = nicif->h2d_off + (uint64_t)H2D_ELEN * H2D_ENUM;
  nicif->n2d_off = nicif->d2n_off + (uint64_t)D2N_ELEN * D2N_ENUM;

  nicif->d2h_queue = (uint8_t *)shmptr + nicif->d2h_off;
  nicif->h2d_queue = (uint8_t *)shmptr + nicif->h2d_off;
  nicif->d2n_queue = (uint8_t *)shmptr + nicif->d2n_off;
  nicif->n2d_queue = (uint8_t *)shmptr + nicif->n2d_off;

  nicif->d2h_pos = nicif->h2d_pos = nicif->d2n_pos = nicif->n2d_pos = 0;
  // get listening sockets ready
  if (params->pci_socket_path != NULL) {
    if ((pci_lfd = uxsocket_init(params->pci_socket_path)) < 0) {
      return -1;
    }
  }
  if (params->eth_socket_path != NULL) {
    if ((eth_lfd = uxsocket_init(params->eth_socket_path)) < 0) {
      return -1;
    }
  }

  // accept connection fds
  if (accept_conns(nicif, di, pci_lfd, &params->sync_pci, eth_lfd,
                   &params->sync_eth) != 0) {
    return -1;
  }


  // receive introductions from other end
  if (params->pci_socket_path != NULL) {
    struct SimbricksProtoPcieHostIntro hi;
    if (recv(nicif->pci_cfd, &hi, sizeof(hi), 0) != sizeof(hi)) {
      return -1;
    }
    if ((hi.flags & SIMBRICKS_PROTO_PCIE_FLAGS_HI_SYNC) == 0)
      params->sync_pci = 0;
    printf("pci host info received\n");
  }
  if (params->eth_socket_path != NULL) {
    struct SimbricksProtoNetNetIntro ni;
    if (recv(nicif->eth_cfd, &ni, sizeof(ni), 0) != sizeof(ni)) {
      return -1;
    }
    if ((ni.flags & SIMBRICKS_PROTO_NET_FLAGS_NI_SYNC) == 0)
      params->sync_eth = 0;
    printf("eth net info received\n");
  }

  nicif->params.sync_pci = params->sync_pci;
  nicif->params.sync_eth = params->sync_eth;
  printf("sycn_pci = %d  sync_eth = %d\n", nicif->params.sync_pci, nicif->params.sync_eth);
  return 0;
}

volatile union SimbricksProtoNetN2D*
SimbricksEtherLink::SimbricksNicIfN2DPoll(
    struct SimbricksNicIf *nicif, uint64_t timestamp)
    {
  volatile union SimbricksProtoNetN2D *msg =
      (volatile union SimbricksProtoNetN2D *)
      (nicif->n2d_queue + nicif->n2d_pos * N2D_ELEN);

  /* message not ready */
  if ((msg->dummy.own_type & SIMBRICKS_PROTO_NET_N2D_OWN_MASK) !=
      SIMBRICKS_PROTO_NET_N2D_OWN_DEV)
    return NULL;

  /* if in sync mode, wait till message is ready */
  nicif->eth_last_rx_time = msg->dummy.timestamp;
  if (nicif->params.sync_eth && nicif->eth_last_rx_time > timestamp)
    return NULL;

  return msg;
}

void
SimbricksEtherLink::SimbricksNicIfN2DDone(struct SimbricksNicIf *nicif,
                           volatile union SimbricksProtoNetN2D *msg) {
  msg->dummy.own_type =
      (msg->dummy.own_type & SIMBRICKS_PROTO_NET_N2D_MSG_MASK) |
      SIMBRICKS_PROTO_NET_N2D_OWN_NET;
}

void
SimbricksEtherLink::SimbricksNicIfN2DNext(struct SimbricksNicIf *nicif) {
  nicif->n2d_pos = (nicif->n2d_pos + 1) % N2D_ENUM;
}

bool
SimbricksEtherLink::pollQueues()
{
    volatile union SimbricksProtoNetN2D *rx_;
    const void *pkt_data;
    size_t pkt_len;

    rx_ = SimbricksNicIfN2DPoll(&nicif_, curTick());

    if (!rx_){
        return false;
    }

    uint8_t type = rx_->dummy.own_type & SIMBRICKS_PROTO_NET_N2D_MSG_MASK;
    if (type == SIMBRICKS_PROTO_NET_N2D_MSG_RECV) {
        DPRINTF(SimbricksEthernet, "receive real packet\n");
        pkt_data = (const void *)rx_->recv.data;
        pkt_len = rx_->recv.len;

        // receive real
        // send to simulator
        EthPacketPtr packet;
        packet = std::make_shared<EthPacketData>(pkt_len);
        packet->length = pkt_len;
        packet->simLength = pkt_len;
        memcpy(packet->data, pkt_data, pkt_len);

        DPRINTF(SimbricksEthernet, "real->sim len=%d\n", packet->length);
        if (!packetBuffer.empty() || !Iface->sendPacket(packet)){

            DPRINTF(SimbricksEthernet, \
            "bus busy...buffer for retransmission\n");

            packetBuffer.push(packet);
            if (!ReTxEvent.scheduled()){
                schedule(ReTxEvent, curTick() + 1000);
            }

            //panic("SimbricksEtherLink interface send packet failed\n");
        }

    } else if (type == SIMBRICKS_PROTO_NET_N2D_MSG_SYNC) {
      // Do nothing
    } else {
      panic("switch_pkt: unsupported type=%u\n", type);
      abort();
    }

    SimbricksNicIfN2DDone(&nicif_, rx_);
    SimbricksNicIfN2DNext(&nicif_);

    return true;
}
void
SimbricksEtherLink::retransmit()
{
    if (packetBuffer.empty())
        return;

    EthPacketPtr packet = packetBuffer.front();
    if (Iface->sendPacket(packet)) {
        DPRINTF(SimbricksEthernet, "SimbricksEthernet retransmit\n");
        packetBuffer.front() = NULL;
        packetBuffer.pop();
    }

    if (!packetBuffer.empty() && !ReTxEvent.scheduled())
        schedule(ReTxEvent, curTick() + 1000);
}

void
SimbricksEtherLink::startup()
{
    if (sync)
        schedule(this->syncTxEvent, curTick());
    schedule(this->pollEvent, curTick() + 1);
}


void
SimbricksEtherLink::processPollEvent()
{
    /* run what we can */
    while (pollQueues());

    if (sync) {
        /* in sychronized mode we might need to wait till we get a message with
         * a timestamp allowing us to proceed */
        while (nicif_.eth_last_rx_time <= curTick()) {
            pollQueues();
        }

        schedule(this->pollEvent, nicif_.eth_last_rx_time);
    } else {
        /* in non-synchronized mode just poll at fixed intervals */
        schedule(this->pollEvent, curTick() + this->pollInterval);
    }
}


volatile union SimbricksProtoNetD2N*
SimbricksEtherLink::SimbricksNicIfD2NAlloc(struct SimbricksNicIf *nicif,
                                        uint64_t timestamp, bool syncAlloc)
{
    volatile union SimbricksProtoNetD2N *msg =
        (volatile union SimbricksProtoNetD2N *)
        (nicif->d2n_queue + nicif->d2n_pos * D2N_ELEN);
    //DPRINTF(SimbricksEthernet, "proto_net_d2n_own_mask: %d\n",
    //SIMBRICKS_PROTO_NET_D2N_OWN_MASK);
    if ((msg->dummy.own_type & SIMBRICKS_PROTO_NET_D2N_OWN_MASK) !=
        SIMBRICKS_PROTO_NET_D2N_OWN_DEV) {
        return NULL;
    }

    msg->dummy.timestamp = timestamp + nicif->params.eth_latency;
    nicif->eth_last_tx_time = timestamp;

    nicif->d2n_pos = (nicif->d2n_pos + 1) % D2N_ENUM;
    if (sync && !syncAlloc)
        reschedule(this->syncTxEvent, curTick() + this->syncTxInterval);

    return msg;
}


void
SimbricksEtherLink::processSyncTxEvent()
{
    volatile union SimbricksProtoNetD2N *d2n = \
                    SimbricksNicIfD2NAlloc(&nicif_, curTick(), true);
    if (d2n == NULL){
        panic("simbricksEtherLink: failed to allocate d2n message\n");
    }

    d2n->sync.own_type = SIMBRICKS_PROTO_NET_D2N_MSG_SYNC \
                        | SIMBRICKS_PROTO_NET_D2N_OWN_NET;
    //DPRINTF(SimbricksEthernet, "schedule sync event at %u\n", curTick());
    schedule(this->syncTxEvent, curTick() + this->syncTxInterval);
}





Port &
SimbricksEtherLink::getPort(const std::string &if_name, PortID idx)
{
    if (if_name == "int0")
        return *Iface;
    return SimObject::getPort(if_name, idx);
}

} // namespace gem5
//} //namespace Simbricks

gem5::SimbricksEtherLink *
SimbricksEtherLinkParams::create()
{
    return new gem5::SimbricksEtherLink(this);
}
