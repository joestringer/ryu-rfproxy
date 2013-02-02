import logging
import itertools

from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.mac import *
from ryu.lib.ip import *
from rflib.defs import *

ADD = 1 
DEL = 2
TMP = 3

def create_default_flow_mod(dp, cookie=0, cookie_mask=0, table_id=0,
                            command=None, idle_timeout=0, hard_timeout=0,
                            priority=OFP_DEFAULT_PRIORITY, 
                            buffer_id=0xffffffff, match=None, actions=None,
                            inst_type=None, out_port=None, out_group=None,
                            flags=0, inst=[]):

  if command is None:
    command = dp.ofproto.OFPFC_ADD

  if inst is []:
    if inst_type is None:
      inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

    inst = []
    if actions is not None:
      inst = [dp.ofproto_parser.OFPInstructionActions(inst_type, actions)]

  if match is None:
    match = dp.ofproto_parser.OFPMatch()

  if out_port is None:
    out_port = dp.ofproto.OFPP_ANY

  if out_group is None:
    out_group = dp.ofproto.OFPG_ANY

  return dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                      table_id, command,
                                      idle_timeout, hard_timeout,
                                      priority, buffer_id,
                                      out_port, out_group,
                                      flags, match, inst)

def conf_flow(dp, ip=None, mask=None, src_hw=None, dst_hw=None, dstPort=None,
              group_id=None, instruction=None):
  if instruction == ADD:
    match = config_match(dp, dl_type=0x0800, src_hw=src_hw, ipv4_dst=ip)
    command = dp.ofproto.OFPFC_ADD
    if (mask == '255.255.255.255'):
        idle_timeout = 300
    else:
        idle_timeout = 0
    hard_timeout = 0
    priority = 0xff
    actions = [dp.ofproto_parser.OFPActionOutput(dstPort, 0)]
    inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
    mod_flow(dp, cookie=0, cookie_mask=0, table_id=0,
          command=command, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
          priority=priority, buffer_id=0xffffffff, match=match,
          actions=None, inst_type=None, out_port=None,
          out_group=None, flags=0, inst=inst)

  if instruction == DEL:
    match = config_match(dp, dl_type=0x0800, src_hw=src_hw, ipv4_dst=ip)
    command = dp.ofproto.OFPFC_DELETE_STRICT
    mod_flow(dp, cookie=0, cookie_mask=0, table_id=0,
          command=command, idle_timeout=0, hard_timeout=0,
          priority=0xff, buffer_id=0xffffffff, match=match,
          actions=None, inst_type=None, out_port=None,
          out_group=None, flags=0, inst=[])

  if instruction == TMP:
    match = config_match(dp, dl_type=0x0800, src_hw=src_hw, ipv4_dst=ip)
    command = dp.ofproto.OFPFC_ADD
    idle_timeout = 60
    out_port = 0
    priority = 0xff
    actions = [dp.ofproto_parser.OFPActionOutput(0, 0)]
    inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
    mod_flow(dp, cookie=0, cookie_mask=0, table_id=0,
             command=command, idle_timeout=idle_timeout, hard_timeout=0,
             priority=priority, buffer_id=0xffffffff, match=match,
             actions=actions, inst_type=None, out_port=None,
             out_group=None, flags=0, inst=inst)


def create_config_msg(dp, operation):
  flow_mod = create_default_flow_mod(dp=dp)
  priority = OFP_DEFAULT_PRIORITY
  port = dp.ofproto.OFPP_CONTROLLER
  actions = [dp.ofproto_parser.OFPActionOutput(port, dp.ofproto.OFPCML_MAX)]
  if operation == DC_RIPV2:
    flow_mod.match.set_dl_type(ETHERTYPE_IP)
    flow_mod.match.set_ip_proto(IPPROTO_UDP)
    flow_mod.match.set_ipv4_dst_masked(ipv4_to_int("224.0.0.9"), 
                                       cidr_to_mask(32))
    priority = OFP_DEFAULT_PRIORITY + 32
  elif operation == DC_OSPF:
    flow_mod.match.set_dl_type(ETHERTYPE_IP)
    flow_mod.match.set_ip_proto(IPPROTO_OSPF)
  elif operation == DC_ARP:
    flow_mod.match.set_dl_type(ETHERTYPE_ARP)
  elif operation == DC_ICMP:
    flow_mod.match.set_dl_type(ETHERTYPE_IP) 
    flow_mod.match.set_ip_proto(IPPROTO_ICMP)
  elif operation == DC_BGP_PASSIVE:
    flow_mod.match.set_dl_type(ETHERTYPE_IP) 
    flow_mod.match.set_ip_proto(IPPROTO_TCP)
    flow_mod.match.set_tcp_dst(TPORT_BGP)
  elif operation == DC_BGP_ACTIVE:
    flow_mod.match.set_dl_type(ETHERTYPE_IP) 
    flow_mod.match.set_ip_proto(IPPROTO_TCP)
    flow_mod.match.set_tcp_src(TPORT_BGP)
  elif operation == DC_LDP_PASSIVE:
    flow_mod.match.set_dl_type(ETHERTYPE_IP) 
    flow_mod.match.set_ip_proto(IPPROTO_TCP)
    flow_mod.match.set_tcp_dst(TPORT_LDP)
  elif operation == DC_LDP_ACTIVE:
    flow_mod.match.set_dl_type(ETHERTYPE_IP) 
    flow_mod.match.set_ip_proto(IPPROTO_TCP)
    flow_mod.match.set_tcp_src(TPORT_LDP)
  elif operation == DC_VM_INFO:
    flow_mod.match.set_dl_type(RF_ETH_PROTO)
  elif operation == DC_DROP_ALL:
    priority = 0x1;
    actions = []
  if operation == DC_CLEAR_FLOW_TABLE:
    flow_mod.command = dp.ofproto.OFPFC_DELETE
    flow_mod.priority = 0x0
  else:
    flow_mod.command = dp.ofproto.OFPFC_ADD
    flow_mod.priority = priority
    inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
    flow_mod.instructions = inst
  return flow_mod

def create_flow_install_msg(dp, ip, mask, srcMac, dstMac, dstPort):
    parser = dp.ofproto_parser
    flow_mod = create_default_flow_mod(dp=dp)
    flow_mod.match.set_dl_type(ETHERTYPE_IP)
    if (MATCH_L2):
        flow_mod.match.set_dl_dst(srcMac)
    flow_mod.match.set_ipv4_dst_masked(ip, cidr_to_mask(mask))
    if mask == 32:
        flow_mod.idle_timeout = 300
    flow_mod.priority = OFP_DEFAULT_PRIORITY + mask
    src = parser.OFPMatchField.make(ofproto_v1_2.OXM_OF_ETH_SRC, srcMac)
    dst = parser.OFPMatchField.make(ofproto_v1_2.OXM_OF_ETH_DST, dstMac)
    actions = [parser.OFPActionSetField(src), parser.OFPActionSetField(dst),
               parser.OFPActionOutput(dstPort, 0)]
    inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS,
                                         actions)]
    flow_mod.instructions = inst
    return flow_mod

def create_flow_remove_msg(dp, ip, mask, srcMac):
    flow_mod = create_default_flow_mod(dp=dp)
    flow_mod.match.set_dl_type(ETHERTYPE_IP)
    if (MATCH_L2):
        flow_mod.match.set_dl_dst(srcMac)
    flow_mod.match.set_ipv4_dst_masked(ip, cidr_to_mask(mask))
    flow_mod.priority = OFP_DEFAULT_PRIORITY + mask
    flow_mod.command = dp.ofproto.OFPFC_DELETE_STRICT
    return flow_mod

def create_temporary_flow_msg(dp, ip, mask, srcMac):
    flow_mod = create_default_flow_mod(dp=dp)
    flow_mod.match.set_dl_type(ETHERTYPE_IP)
    if (MATCH_L2):
        flow_mod.match.set_dl_dst(srcMac)
    flow_mod.match.set_ipv4_dst_masked(ip, cidr_to_mask(mask))
    flow_mod.priority = OFP_DEFAULT_PRIORITY + mask
    flow_mod.idle_timeout = 60
    actions = []
    inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
    flow_mod.instructions = inst
    return flow_mod

def send_pkt_out(dp, port, msg):
  actions = [dp.ofproto_parser.OFPActionOutput(port, len(msg)), ]
  dp.send_packet_out(buffer_id=0xffffffff, in_port=dp.ofproto.OFPP_ANY, actions=actions, data=msg)  
