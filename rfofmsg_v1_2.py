import logging
import itertools

from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.lib.mac import *
from ryu.lib.ip import *
from ryu.app.rflib.defs import *

ADD = 1 
DEL = 2
TMP = 3

def mod_flow(dp, cookie=0, cookie_mask=0, table_id=0,
					command=None, idle_timeout=0, hard_timeout=0,
					priority=0xff, buffer_id=0xffffffff, match=None,
					actions=None, inst_type=None, out_port=None,
					out_group=None, flags=0, inst=[]):

	if command is None:
		command = dp.ofproto.OFPFC_ADD

	if inst is []:
		if inst_type is None:
			inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

		inst = []
		if actions is not None:
			inst = [dp.ofproto_parser.OFPInstructionActions(inst_type, actions), ]

	if match is None:
		match = dp.ofproto_parser.OFPMatch()

	if out_port is None:
		out_port = dp.ofproto.OFPP_ANY

	if out_group is None:
		out_group = dp.ofproto.OFPG_ANY


	m = dp.ofproto_parser.OFPFlowMod(dp, cookie, cookie_mask,
                                         table_id, command,
                                         idle_timeout, hard_timeout,
                                         priority, buffer_id,
                                         out_port, out_group,
                                         flags, match, inst)
	dp.send_msg(m)


def config_match(dp, mpls_label=None, dl_type=None, proto=None, mpls=None,
					ipv4_src=None, mask_src=None, ipv4_dst=None, mask_dst=None, port=None, src_hw=None, dst_hw=None):
	match = dp.ofproto_parser.OFPMatch()
	if dl_type is not None:
		match.set_dl_type(dl_type)
	if mpls_label is not None:
		match.set_dl_type(0x8847)
		match.set_mpls_label(mpls_label)
	if proto is not None:
		match.set_ip_proto(proto)
	if ipv4_src is not None:
		if mask_src is not None:
			match.set_ipv4_src_masked(ipv4_src, mask_src)
		else:
			match.set_ipv4_dst(ipv4_src)
	if ipv4_dst is not None:
		if mask_dst is not None:
			match.set_ipv4_dst_masked(ipv4_dst, mask_dst)
		else:
			match.set_ipv4_dst(ipv4_dst)
	if port is not None:
		match.set_in_port(port)
	if src_hw is not None:
		match.set_dl_src(src_hw)
	if dst_hw is not None:
		match.set_dl_dst(dst_hw)
	return match


def conf_flow(dp, ip=None, mask=None, src_hw=None, dst_hw=None, dstPort=None, group_id=None, instruction=None):
	if instruction == ADD:
		match = config_match(dp, dl_type=0x0800, src_hw=src_hw, ipv4_dst=ip)
		command = dp.ofproto.OFPFC_ADD
		if (mask == '255.255.255.255'):
				idle_timeout = 300
    		else:
				idle_timeout = 0
		hard_timeout = 0
		priority = 0xff
		actions = [dp.ofproto_parser.OFPActionOutput(dstPort, 0), ]
		inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions), ]
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
		actions = [dp.ofproto_parser.OFPActionOutput(0, 0), ]
		inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions), ]
		mod_flow(dp, cookie=0, cookie_mask=0, table_id=0,
					command=command, idle_timeout=idle_timeout, hard_timeout=0,
					priority=priority, buffer_id=0xffffffff, match=match,
					actions=actions, inst_type=None, out_port=None,
					out_group=None, flags=0, inst=inst)


def create_config_msg(dp, operation):
	priority=0
	match = config_match(dp)

	if operation == DC_RIPV2:
		match = config_match(dp, dl_type=0x0800, proto=17, ipv4_src=ipv4_to_int("224.0.0.9"))
	elif operation == DC_OSPF:
		match = config_match(dp, dl_type=0x0800, proto=89)
	elif operation == DC_ARP:
		match = config_match(dp, dl_type=0x0806)
	elif operation == DC_ICMP:
		match = config_match(dp, dl_type=0x0800, proto=1)
	elif operation == DC_BGP_ACTIVE or operation == DC_BGP_PASSIVE:
		match = config_match(dp, dl_type=0x0800, proto=6)
	elif operation == DC_VM_INFO:
		match = config_match(dp, dl_type=RF_ETH_PROTO)
	elif operation == DC_DROP_ALL:
		priority = 0xff;
		match = config_match(dp)
	elif operation == DC_ALL:
		match = config_match(dp)
	if operation == DC_CLEAR_FLOW_TABLE:
		command = dp.ofproto.OFPFC_DELETE
		priority = 0xff
		idle_timeout = 0
		hard_timeout = 0
		mod_flow(dp, cookie=0, cookie_mask=0, table_id=1,
					command=command, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
					priority=priority, buffer_id=0xffffffff, match=None,
					actions=None, inst_type=None, out_port=None,
					out_group=None, flags=0, inst=[])
	else:
		command = dp.ofproto.OFPFC_ADD
		idle_timeout = 0
		hard_timeout = 0
		port = dp.ofproto.OFPP_CONTROLLER
		actions = [dp.ofproto_parser.OFPActionOutput(port, 0), ]
		inst = [dp.ofproto_parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions), ]
		mod_flow(dp, cookie=0, cookie_mask=0, table_id=1,
					command=command, idle_timeout=idle_timeout, hard_timeout=hard_timeout,
					priority=priority, buffer_id=0xffffffff, match=match,
					actions=actions, inst_type=None, out_port=None,
					out_group=None, flags=0, inst=inst)

		inst = [dp.ofproto_parser.OFPInstructionGotoTable(1), ]
		mod_flow(dp, cookie=0, cookie_mask=0, table_id=0,
					command=command, idle_timeout=0, hard_timeout=0,
					priority=0, buffer_id=0xffffffff, match=None,
					actions=None, inst_type=None, out_port=None,
					out_group=None, flags=0, inst=inst)


def send_pkt_out(dp, port, in_port, msg):
	actions = [dp.ofproto_parser.OFPActionOutput(port, len(msg.data)), ]
	dp.send_packet_out(buffer_id=0xffffffff, in_port=dp.ofproto.OFPP_ANY, actions=actions, data=msg.data)	
