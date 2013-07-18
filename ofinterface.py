import logging

from rflib.defs import *
from binascii import *
from rflib.types.Match import *
from rflib.types.Action import *
from rflib.types.Option import *

OFP_BUFFER_NONE = 0xffffffff
log = logging.getLogger('ryu.app.rfproxy')


def create_default_flow_mod(dp, cookie=0, cookie_mask=0, table_id=0,
                            command=None, idle_timeout=0, hard_timeout=0,
                            priority=PRIORITY_LOWEST,
                            buffer_id=0xffffffff, match=None, actions=None,
                            inst_type=None, out_port=None, out_group=None,
                            flags=0, inst=[]):

    if command is None:
        command = dp.ofproto.OFPFC_ADD

    if inst is []:
        if inst_type is None:
            inst_type = dp.ofproto.OFPIT_APPLY_ACTIONS

        if actions is not None:
            inst = [dp.ofproto_parser.OFPInstructionActions(inst_type,
                                                            actions)]

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


def create_flow_mod(dp, mod, matches, actions, options):
    flow_mod = create_default_flow_mod(dp)
    add_command(flow_mod, mod)
    add_matches(flow_mod, matches)
    add_actions(flow_mod, actions)
    add_options(flow_mod, options)
    return flow_mod


def add_command(flow_mod, mod):
    if mod == RMT_ADD:
        pass
    elif mod == RMT_DELETE:
        flow_mod.command = flow_mod.datapath.ofproto.OFPFC_DELETE_STRICT


def add_matches(flow_mod, matches):
    for m in matches:
        match = Match.from_dict(m)
        if match._type == RFMT_IPV4:
            value = bin_to_int(match._value)
            addr = value >> 32
            mask = value & ((1 << 32) - 1)
            flow_mod.match.set_dl_type(ETHERTYPE_IP)
            flow_mod.match.set_ipv4_dst_masked(addr, mask)
        elif match._type == RFMT_IPV6:
            v = match._value
            addr = tuple((ord(v[i]) << 8) | ord(v[i + 1])
                         for i in range(0, 16, 2))
            mask = tuple((ord(v[i]) << 8) | ord(v[i + 1])
                         for i in range(16, 32, 2))
            flow_mod.match.set_dl_type(ETHERTYPE_IPV6)
            flow_mod.match.set_ipv6_dst_masked(addr, mask)
        elif match._type == RFMT_ETHERNET:
            flow_mod.match.set_dl_dst(match._value)
        elif match._type == RFMT_ETHERTYPE:
            flow_mod.match.set_dl_type(bin_to_int(match._value))
        elif match._type == RFMT_NW_PROTO:
            flow_mod.match.set_ip_proto(bin_to_int(match._value))
        elif match._type == RFMT_TP_SRC:
            flow_mod.match.set_ip_proto(IPPROTO_TCP)
            flow_mod.match.set_tcp_src(bin_to_int(match._value))
        elif match._type == RFMT_TP_DST:
            flow_mod.match.set_ip_proto(IPPROTO_TCP)
            flow_mod.match.set_tcp_dst(bin_to_int(match._value))
        elif match._type == RFMT_IN_PORT:
            flow_mod.match.set_in_port(bin_to_int(match._value))
        elif TLV.optional(match):
            log.info("Dropping unsupported Match (type: %s)" % match._type)
        else:
            log.warning("Failed to serialise Match (type: %s)" % match._type)
            return


def add_actions(flow_mod, action_tlvs):
    parser = flow_mod.datapath.ofproto_parser
    ofproto = flow_mod.datapath.ofproto
    actions = []
    for a in action_tlvs:
        action = Action.from_dict(a)
        if action._type == RFAT_OUTPUT:
            port = bin_to_int(action._value)
            a = parser.OFPActionOutput(port, ofproto.OFPCML_MAX)
            actions.append(a)
        elif action._type == RFAT_SET_ETH_SRC:
            srcMac = action._value
            src = parser.OFPMatchField.make(ofproto.OXM_OF_ETH_SRC, srcMac)
            actions.append(parser.OFPActionSetField(src))
        elif action._type == RFAT_SET_ETH_DST:
            dstMac = action._value
            dst = parser.OFPMatchField.make(ofproto.OXM_OF_ETH_DST, dstMac)
            actions.append(parser.OFPActionSetField(dst))
        elif action.optional():
            log.info("Dropping unsupported Action (type: %s)" % action._type)
        else:
            log.warning("Failed to serialise Action (type: %s)" % action._type)
            return
    inst = parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
    flow_mod.instructions = [inst]


def add_options(flow_mod, options):
    for o in options:
        option = Option.from_dict(o)
        if option._type == RFOT_PRIORITY:
            flow_mod.priority = bin_to_int(option._value)
        elif option._type == RFOT_IDLE_TIMEOUT:
            flow_mod.idle_timeout = bin_to_int(option._value)
        elif option._type == RFOT_HARD_TIMEOUT:
            flow_mod.hard_timeout = bin_to_int(option._value)
        elif option._type == RFOT_CT_ID:
            pass
        elif option.optional():
            log.info("Dropping unsupported Option (type: %s)" % option._type)
        else:
            log.warning("Failed to serialise Option (type: %s)" % option._type)
            return


def send_pkt_out(dp, port, msg_data):
    actions = []
    actions.append(dp.ofproto_parser.OFPActionOutput(port, len(msg_data)))
    buffer_id = OFP_BUFFER_NONE
    in_port = dp.ofproto.OFPP_ANY
    packet_out = dp.ofproto_parser.OFPPacketOut(dp, buffer_id, in_port,
                                                actions, msg_data)
    dp.send_msg(packet_out)
