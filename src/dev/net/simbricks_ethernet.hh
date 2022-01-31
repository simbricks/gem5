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

#ifndef __DEV_NET_SIMBRICKSETHERLINK_HH__
#define __DEV_NET_SIMBRICKSETHERLINK_HH__

#include <simbricks/nicif/nicif.h>
#include <simbricks/proto/base.h>
#include <simbricks/proto/network.h>
#include <simbricks/proto/pcie.h>

#include <queue>
#include <utility>

#include "base/types.hh"
#include "dev/net/etherint.hh"
#include "dev/net/etherpkt.hh"
#include "params/SimbricksEtherLink.hh"
#include "sim/eventq.hh"
#include "sim/sim_object.hh"

//namespace Simbricks{
namespace gem5{

class EtherDump;
class Checkpoint;

class SimbricksEtherLink : public SimObject
{

protected:
  class Interface;


  class Interface : public EtherInt
  {
    private:
      SimbricksEtherLink *txlink;
    public:
      Interface(const std::string &name, SimbricksEtherLink *t);

      bool recvPacket(EthPacketPtr pkt) override
          { return txlink->recvSimulated(pkt); }
      void sendDone() override {}
      //bool isBusy() { return false; }
  };

protected:
  Interface *Iface;

public:
  using Params = SimbricksEtherLinkParams;
  SimbricksEtherLink(const Params *p);
  virtual ~SimbricksEtherLink();
  bool recvSimulated(EthPacketPtr packet);
  Port &getPort(const std::string &if_name,
                  PortID idx=InvalidPortID) override;
  //virtual void serialize(CheckpointOut &cp) const override;
  //virtual void unserialize(CheckpointIn &cp) override;
private:
  uint64_t eth_delay;
  int pollInterval;
  int syncTxInterval;

  bool sync;
  int sync_mode;

  void *shmptr;
  size_t shm_size;

  struct SimbricksNicIf nicif_;
  struct SimbricksNicIfParams params;
  struct SimbricksProtoPcieDevIntro di;

  int shm_create(const char *path, size_t size, void **addr);
  int uxsocket_init(const char *path);
  int uxsocket_send(int connfd, void *data, size_t len, int fd);

  int accept_pci(struct SimbricksNicIf *nicif,
                      struct SimbricksProtoPcieDevIntro *di,
                      int pci_lfd,
                      int *sync_pci);
  int accept_eth(struct SimbricksNicIf *nicif,
                      int eth_lfd,
                      int *sync_eth);
  int accept_conns(struct SimbricksNicIf *nicif,
                        struct SimbricksProtoPcieDevIntro *di, int pci_lfd,
                        int *sync_pci, int eth_lfd, int *sync_eth);

  int SimbricksNicIfInit(struct SimbricksNicIf *nicif,
                       struct SimbricksNicIfParams *params,
                       struct SimbricksProtoPcieDevIntro *di);
  volatile union SimbricksProtoNetD2N*
  SimbricksNicIfD2NAlloc(struct SimbricksNicIf *nicif, \
  uint64_t timestamp, bool isSync=false);
  volatile union SimbricksProtoNetN2D*
  SimbricksNicIfN2DPoll(struct SimbricksNicIf *nicif, uint64_t timestamp);

  void init() override;
  virtual void startup() override;
  void processPollEvent();
  void processSyncTxEvent();
  EventFunctionWrapper pollEvent;
  EventFunctionWrapper syncTxEvent;
  void SimbricksNicIfN2DDone(struct SimbricksNicIf *nicif,
                           volatile union SimbricksProtoNetN2D *msg);
  void SimbricksNicIfN2DNext(struct SimbricksNicIf *nicif);
  bool pollQueues();

/*

  volatile union SimbricksProtoNetN2D *SimbricksNicIfN2DPoll(
  struct SimbricksNicIfParams *params, uint64_t timestamp);
  void SimbricksNicIfN2DDone(volatile union SimbricksProtoNetN2D *msg);
  void SimbricksNicIfN2DNext(void);

  volatile union SimbricksProtoNetD2N *SimbricksNicIfD2NAlloc(
  struct SimbricksNicIfParams *params, uint64_t timestamp);



  static int shm_fd;
  static int eth_cfd;

*/
  std::queue<EthPacketPtr> packetBuffer;
  void retransmit();
  EventFunctionWrapper ReTxEvent;
};

} // namespace gem5
//} // namespace simbricks
#endif // __DEV_NET_SIMBRICKSETHERLINK_HH__
