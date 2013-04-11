import struct
import logging
import gevent

import pymongo as mongo

from ofinterface import *

import rflib.ipc.IPC as IPC
import rflib.ipc.MongoIPC as MongoIPC
from rflib.ipc.RFProtocol import *
from rflib.ipc.RFProtocolFactory import RFProtocolFactory
from rflib.defs import *

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import *
from ryu.ofproto import ofproto_v1_2
from ryu.lib.mac import *
from ryu.lib.ip import *
from ryu.lib.dpid import *
from ryu.controller import dpset

log = logging.getLogger('ryu.app.rfproxy')

ADD = 1
DEL = 2

#Datapath <-> dp_id association
class Datapaths:
  def __init__(self):
    self.dps = {}   # datapath_id => class Datapath

  def register(self, dp):
    assert dp.id is not None
    assert dp.id not in self.dps
    self.dps[dp.id] = dp

  def unregister(self, dp):
    if dp.id in self.dps:
      del self.dps[dp.id]

  def get(self, dp_id):
    return self.dps.get(dp_id, None)


# Association table
class Table:
  def __init__(self):
    self.dp_to_vs = {}
    self.vs_to_dp = {}

  def update_dp_port(self, dp_id, dp_port, vs_id, vs_port):
        # If there was a mapping for this DP port, reset it
    if (dp_id, dp_port) in self.dp_to_vs:
      old_vs_port = self.dp_to_vs[(dp_id, dp_port)]
      del self.vs_to_dp[old_vs_port]
    self.dp_to_vs[(dp_id, dp_port)] = (vs_id, vs_port)
    self.vs_to_dp[(vs_id, vs_port)] = (dp_id, dp_port)

  def dp_port_to_vs_port(self, dp_id, dp_port):
    try:
      return self.dp_to_vs[(dp_id, dp_port)]
    except KeyError:
      return None

  def vs_port_to_dp_port(self, vs_id, vs_port):
    try:
      return self.vs_to_dp[(vs_id, vs_port)]
    except KeyError:
      return None

  def delete_dp(self, dp_id):
    for (id_, port) in self.dp_to_vs.keys():
      if id_ == dp_id:
        del self.dp_to_vs[(id_, port)]

    for key in self.vs_to_dp.keys():
      id_, port = self.vs_to_dp[key]
      if id_ == dp_id:
        del self.vs_to_dp[key]
                    
    # We're not considering the case of this table becoming invalid when a
    # datapath goes down. When the datapath comes back, the server recreates
    # the association, forcing new map messages to be generated, overriding the
    # previous mapping.
    # If a packet comes and matches the invalid mapping, it can be redirected
    # to the wrong places. We have to fix this.

def gevent_thread_wrapper(target, args=()):
    return gevent.spawn(target, *args)

ID = 0
ipc = MongoIPC.MongoIPCMessageService(MONGO_ADDRESS, MONGO_DB_NAME, str(ID),
                                      gevent_thread_wrapper, gevent.sleep)
table = Table()
datapaths = Datapaths()

# IPC message Processing
class RFProcessor(IPC.IPCMessageProcessor):
  def process(self, from_, to, channel, msg):
    type_ = msg.get_type()
    if type_ == ROUTE_MOD:
      dp = datapaths.get(msg.get_id())
      ofmsg = create_flow_mod(dp, msg.get_mod(), msg.get_matches(),
                              msg.get_actions(), msg.get_options())
      try:
        dp.send_msg(ofmsg)
      except Exception as e:
        log.info("Error sending RouteMod:")
        log.info(type(e))
        log.info(str(e))
      else:
        log.info("ofp_flow_mod was sent to datapath (dp_id = %s)",
                 msg.get_id())
    if type_ == DATA_PLANE_MAP:
      table.update_dp_port(msg.get_dp_id(), msg.get_dp_port(),
      msg.get_vs_id(), msg.get_vs_port())
    return True


class RFProxy(app_manager.RyuApp):
  #Listen to DPSet event which defines datapath enter=true or enter=false
  _CONTEXTS = {'dpset': dpset.DPSet}

  OFP_VERSIONS = [ofproto_v1_2.OFP_VERSION]

  def __init__(self, *args, **kwargs):
    super(RFProxy, self).__init__(*args, **kwargs)
    ipc.listen(RFSERVER_RFPROXY_CHANNEL, RFProtocolFactory(), RFProcessor(),
               False)
    log.info("RFProxy running.")

  #Event handlers
  @set_ev_cls(dpset.EventDP, dpset.DPSET_EV_DISPATCHER)
  def handler_datapath(self, ev):
    dp = ev.dp
    dpid = dp.id
    ports = dp.ports
    if ev.enter:
      log.info("Datapath is up (dp_id=%s)", dpid_to_str(dpid))
      datapaths.register(dp)
      for port in ports:
        if port <= ofproto_v1_2.OFPP_MAX:
          msg = DatapathPortRegister(dp_id=dpid, dp_port=port)
          ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)
          log.info("Registering datapath port (dp_id=%s, dp_port=%d)", dpid_to_str(dpid), port)
    else:                  
      log.info("Datapath is down (dp_id=%s)", dpid_to_str(dpid))
      datapaths.unregister(dp)
      table.delete_dp(dpid)
      msg = DatapathDown(dp_id=dpid)
      ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)


  @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
  def on_packet_in(self, ev):
    msg = ev.msg
    dp = msg.datapath
    dpid = dp.id
    dst, src, _eth_type = struct.unpack_from('!6s6sH', buffer(msg.data), 0)
    for f in msg.match.fields:
      if f.header == ofproto_v1_2.OXM_OF_IN_PORT:
        in_port = f.value

    # Drop all LLDP packets
    #ADD LLDP_TYPE to ryu.ofproto.ether
    #if _eth_type == LLDP_TYPE:
    #    return
        
    # If we have a mapping packet, inform RFServer through a Map message
    if _eth_type == RF_ETH_PROTO:
      vm_id, vm_port = struct.unpack("QB", msg.data[14:23])
      log.info("Received mapping packet (vm_id=%s, vm_port=%d, vs_id=%s, vs_port=%d)",
            format_id(vm_id), vm_port, dpid_to_str(dpid), in_port)
      msg = VirtualPlaneMap(vm_id=vm_id, vm_port=vm_port, vs_id=dpid, vs_port=in_port)
      ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)
      return

    # If the packet came from RFVS, redirect it to the right switch port
    if is_rfvs(dpid):
      dp_port = table.vs_port_to_dp_port(dpid, in_port)
      if dp_port is not None:
        dp_id, dp_port = dp_port
        send_pkt_out(datapaths.get(dp_id), dp_port, msg.data)
        log.info("forwarding packet from rfvs (dp_id: %s, dp_port: %d)", dpid_to_str(dp_id), dp_port)
      else:
        log.info("Unmapped RFVS port (vs_id=%s, vs_port=%d)", dpid_to_str(dpid), in_port)
    # If the packet came from a switch, redirect it to the right RFVS port
    else:
      vs_port = table.dp_port_to_vs_port(dpid, in_port)
      if vs_port is not None:
        vs_id, vs_port = vs_port
        send_pkt_out(datapaths.get(vs_id), vs_port, msg.data)
        log.info("forwarding packet to rfvs (vs_id: %s, vs_port: %d)", dpid_to_str(vs_id), vs_port)
      else:
        log.info("Unmapped datapath port (dp_id=%s, dp_port=%d)", dpid_to_str(dpid), in_port)
