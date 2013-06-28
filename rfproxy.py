import struct
import logging

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
from ryu.topology import switches, event
from ryu.ofproto import ofproto_v1_2 as ofproto
from ryu.lib.mac import *
from ryu.lib.dpid import *
from ryu.lib import hub
from ryu.lib.packet.ethernet import ethernet

log = logging.getLogger('ryu.app.rfproxy')


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


def hub_thread_wrapper(target, args=()):
        result = hub.spawn(target, *args)
        result.start = lambda: target
        return result

table = Table()


# IPC message Processing
class RFProcessor(IPC.IPCMessageProcessor):

    def __init__(self, switches):
        self._switches = switches

    def process(self, from_, to, channel, msg):
        type_ = msg.get_type()
        if type_ == ROUTE_MOD:
            switch = self._switches._get_switch(msg.get_id())
            dp = switch.dp
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
    #Listen to the Ryu topology change events
    _CONTEXTS = {
                'switches': switches.Switches,
                }
    OFP_VERSIONS = [ofproto.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RFProxy, self).__init__(*args, **kwargs)

        self.ID = 0
        self.ipc = MongoIPC.MongoIPCMessageService(MONGO_ADDRESS,
                                                   MONGO_DB_NAME, str(self.ID),
                                                   hub_thread_wrapper,
                                                   hub.sleep)
        self.switches = kwargs['switches']
        self.rfprocess = RFProcessor(self.switches)

        self.ipc.listen(RFSERVER_RFPROXY_CHANNEL, RFProtocolFactory(),
                        self.rfprocess, False)
        log.info("RFProxy running.")

    #Event handlers
    @set_ev_cls(event.EventSwitchEnter, MAIN_DISPATCHER)
    def handler_datapath_enter(self, ev):
        dp = ev.switch.dp
        ports = ev.switch.ports
        dpid = dp.id
        log.debug("INFO:rfproxy:Datapath is up (dp_id=%d)", dpid)
        for port in ports:
            if port.port_no <= dp.ofproto.OFPP_MAX:
                msg = DatapathPortRegister(ct_id=self.ID, dp_id=dpid,
                                           dp_port=port.port_no)
                self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)
                log.info("Registering datapath port (dp_id=%s, dp_port=%d)",
                         dpid_to_str(dpid), port.port_no)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def handler_datapath_leave(self, ev):
        dp = ev.switch.dp
        dpid = dp.id
        log.info("Datapath is down (dp_id=%d)", dpid)
        table.delete_dp(dpid)
        msg = DatapathDown(ct_id=self.ID, dp_id=dpid)
        self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def on_packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        pkt, _ = ethernet.parser(msg.data)

        for f in msg.match.fields:
            if f.header == dp.ofproto.OXM_OF_IN_PORT:
                in_port = f.value

        # If we have a mapping packet, inform RFServer through a Map message
        if pkt.ethertype == RF_ETH_PROTO:
            vm_id, vm_port = struct.unpack("QB", msg.data[14:23])
            log.info("Received mapping packet (vm_id=%s, vm_port=%d, "
                     "vs_id=%s, vs_port=%d)", format_id(vm_id), vm_port,
                     dpid_to_str(dpid), in_port)
            msg = VirtualPlaneMap(vm_id=vm_id, vm_port=vm_port, vs_id=dpid,
                                  vs_port=in_port)
            self.ipc.send(RFSERVER_RFPROXY_CHANNEL, RFSERVER_ID, msg)
            return

        # If the packet came from RFVS, redirect it to the right switch port
        if is_rfvs(dpid):
            dp_port = table.vs_port_to_dp_port(dpid, in_port)
            if dp_port is not None:
                dp_id, dp_port = dp_port
                switch = self.switches._get_switch(dp_id)
                if switch is not None:
                    send_pkt_out(switch.dp, dp_port, msg.data)
                    log.debug("forwarding packet from rfvs (dp_id: %s, "
                             "dp_port: %d)", dpid_to_str(dp_id), dp_port)
                else:
                    log.warn("dropped packet from rfvs (dp_id: %s, "
                             "dp_port: %d)", dpid_to_str(dp_id), dp_port)
            else:
                log.info("Unmapped RFVS port (vs_id=%s, vs_port=%d)",
                         dpid_to_str(dpid), in_port)
        # If the packet came from a switch, redirect it to the right RFVS port
        else:
            vs_port = table.dp_port_to_vs_port(dpid, in_port)
            if vs_port is not None:
                vs_id, vs_port = vs_port
                switch = self.switches._get_switch(vs_id)
                if switch is not None:
                    send_pkt_out(switch.dp, vs_port, msg.data)
                    log.debug("forwarding packet to rfvs (vs_id: %s, "
                              "vs_port: %d)", dpid_to_str(vs_id), vs_port)
                else:
                    log.warn("dropped packet to rfvs (vs_id: %s, "
                             "vs_port: %d)", dpid_to_str(dp_id), dp_port)
            else:
                log.info("Unmapped datapath port (dp_id=%s, dp_port=%d)",
                         dpid_to_str(dpid), in_port)
