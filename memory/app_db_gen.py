#!/bin/python3

import random
import redis
import collections
import ipaddress
import uuid
import struct


VNET_COUNT = 1024
ENI_COUNT = 64
OUTBOUND_ROUTES_PER_ENI = 100 * 1000
INBOUND_ROUTES_PER_ENI = 10 * 1000
NSG_PER_ENI = 10
ACL_RULES_PER_NSG = 1000
ACL_PREFIXES_PER_ENI = 10 * 100 * 1000
MAX_PREFIXES_PER_RULE = 8 * 1000
ACL_PORTS_PER_ENI = 10 * 10 * 1000
CA_PA_MAPPING = 10 * 1000 * 1000
ACTIVE_CONNECTIONS_PER_ENI = 1000 * 1000
TOTAL_ACTIVE_CONNECTIONS = 32 * 1000 * 1000
METERING_BUCKES_PER_ENI = 4 * 1000
CPS = 1.5 * 1000 * 1000

FIXED_ENI = "F4939FEFC47E"
FIXED_VNI = 2000
FIXED_MAC = "F9:22:83:99:22:A2"

# Dev settings

# VNET_COUNT = 4
# NSG_PER_ENI = 4
# ACL_RULES_PER_NSG = 4
# ACL_PREFIXES_PER_ENI = 4
# MAX_PREFIXES_PER_RULE = 4
# ACL_PORTS_PER_ENI = 4

# OPTIONS
INCLUDE_ACL = True
ACL_INCLUDE_PREFIX = True
SAVE_PREFIX_AS_BINARY = False
USE_TAG = True
TABLE_NAME_AS_BINARY = False
TABLE_SET = {}

def insert_entry(rp, table, key, values):
    for k, v in values.items():
        if isinstance(v, list):
            if v and isinstance(v[0], ipaddress.IPv6Network):
                # values[k] = ",".join([x.exploded for x in v])
                values[k] = b""
                if SAVE_PREFIX_AS_BINARY:
                    for x in v:
                            values[k] += (x.network_address.packed + struct.pack("B", x.prefixlen))
                else:
                    values[k] = ",".join([x.exploded for x in v])
            else:
                values[k] = ",".join([str(x) for x in v])
        else:
            values[k] = str(v)
    if hasattr(key, "__iter__") and not isinstance(key, str):
        key = ":".join([str(x) for x in key])
    if TABLE_NAME_AS_BINARY:
        if table not in TABLE_SET:
            TABLE_SET[table] = len(TABLE_SET)
        table = struct.pack("B", TABLE_SET[table])
        key = table + b":" + str(key).encode("utf-8")
    else:
        key = table + ":" + str(key)
    rp.hset(key, mapping=values)


class FieldGenerator(object):
    def __init__(self):
        self.vnet_id = 0
        self.vni = 0
        self.prefix_id = collections.defaultdict(int)
        self.address_id = collections.defaultdict(int)
        self.port_id = collections.defaultdict(int)
        self.protocol_id = collections.defaultdict(int)
        self.acl_group_id = 0
        self.mac_id = 0

    def gen_vnet_name(self):
        self.vnet_id += 1
        return "vnet" + str(self.vnet_id)

    def pick_vnet_name(self):
        return "vnet" + str(random.randint(1, self.vnet_id))

    def gen_vni(self):
        self.vnet_id += 1
        return self.vni

    def gen_prefix(self, key=None, is_ipv4=False):
        self.prefix_id[key] += 1
        if is_ipv4:
            prefix = ipaddress.IPv4Network(self.prefix_id[key], strict=False)
        else:
            prefix = ipaddress.IPv6Network(self.prefix_id[key], strict=False)
        return prefix

    def gen_ip(self, key=None, is_ipv4=False):
        self.address_id[key] += 1
        if is_ipv4:
            address = ipaddress.IPv4Address(self.address_id[key])
        else:
            address = ipaddress.IPv6Address(self.address_id[key])
        return address

    def gen_port(self, key=None):
        self.port_id[key] += 1
        return self.port_id[key] % 65536

    def gen_port_range(self, key=None):
        start = self.gen_port(key)
        end = self.gen_port(key)
        if start < end:
            return (start, end)
        else:
            return (end, start)

    def gen_protocol(self, key=None):
        self.protocol_id[key] += 1
        return self.protocol_id[key] % 256

    def gen_guid(self):
        return uuid.uuid4()

    def gen_acl_group_id(self):
        self.acl_group_id += 1
        return self.acl_group_id

    def pick_acl_group_id(self):
        return random.randint(1, self.acl_group_id)


def gen_list(gen_func, count=10):
    if count <= 1:
        count = 1
    return [gen_func() for i in range(int(count))]


def gen_vnets(rp, fg):
    for i in range(VNET_COUNT):
        insert_entry(
            rp,
            "DASH_VNET_TABLE",
            fg.gen_vnet_name(),
            {
                "vni": fg.gen_vni(),
                "guid": fg.gen_guid(),
                "address_space": gen_list(fg.gen_prefix),
                "peer_list": gen_list(fg.pick_vnet_name),
            })
        print("DASH_VNET_TABLE", i, "/", VNET_COUNT)


def gen_acl(rp, fg):
    for i in range(NSG_PER_ENI):
        insert_entry(
            rp,
            "DASH_ACL_GROUP_TABLE",
            fg.gen_acl_group_id(),
            {
                "ip_version": "ipv6",
                "guid": fg.gen_guid(),
            })
        insert_entry(
            rp,
            "DASH_ACL_IN_TABLE",
            (FIXED_ENI, fg.pick_acl_group_id()),
            {
                "acl_group_id": fg.pick_acl_group_id(),
            }
        )
        insert_entry(
            rp,
            "DASH_ACL_OUT_TABLE",
            (FIXED_ENI, fg.pick_acl_group_id()),
            {
                "acl_group_id": fg.pick_acl_group_id(),
            }
        )
        print("DASH_ACL_GROUP_TABLE", i, "/", NSG_PER_ENI)

    rule_per_eni = ACL_RULES_PER_NSG * NSG_PER_ENI
    if not USE_TAG:
        prefix_pool = gen_list(fg.gen_prefix, ACL_PREFIXES_PER_ENI / rule_per_eni)
        prefix_per_rule = MAX_PREFIXES_PER_RULE
    else:
        prefix_pool = gen_list(fg.gen_prefix, ACL_PREFIXES_PER_ENI)
    # prefix_pool = [0] * int(ACL_PREFIXES_PER_ENI / rule_per_eni)
    prefix_selector = 0
    port_per_rule = ACL_PORTS_PER_ENI / rule_per_eni

    if USE_TAG:
        for i in range(32):
            prefix = []
            while len(prefix) < MAX_PREFIXES_PER_RULE:
                if prefix_selector >= len(prefix_pool):
                    prefix_selector = 0
                if prefix_selector + MAX_PREFIXES_PER_RULE > len(prefix_pool):
                    prefix += prefix_pool[prefix_selector:]
                    prefix_selector = 0
                else:
                    prefix = prefix_pool[prefix_selector: prefix_selector +
                                        MAX_PREFIXES_PER_RULE]
                    prefix_selector += MAX_PREFIXES_PER_RULE
            insert_entry(
                rp,
                "DASH_PREFIX_TAG_TABLE",
                i,
                {
                    "prefix_list": prefix,
                }
            )
        prefix_pool = prefix_pool[MAX_PREFIXES_PER_RULE * 32:]
        prefix_per_rule = int(len(prefix_pool) / rule_per_eni)

    for i in range(NSG_PER_ENI):
        for j in range(ACL_RULES_PER_NSG):
            prefix = []
            if ACL_INCLUDE_PREFIX:
                while len(prefix) < prefix_per_rule:
                    if prefix_selector >= len(prefix_pool):
                        prefix_selector = 0
                    if prefix_selector + prefix_per_rule > len(prefix_pool):
                        prefix += prefix_pool[prefix_selector:]
                        prefix_selector = 0
                    else:
                        prefix = prefix_pool[prefix_selector: prefix_selector +
                                            prefix_per_rule]
                        prefix_selector += prefix_per_rule
            insert_entry(
                rp,
                "DASH_ACL_RULE_TABLE",
                (fg.pick_acl_group_id(), i * ACL_RULES_PER_NSG + j),
                {
                    "priority": 2**32-1,
                    "action": "allow",
                    "terminating": True,
                    "protocol": gen_list(fg.gen_protocol, 255),
                    "src_addr": prefix[: int(len(prefix) / 2)],
                    "dst_addr": prefix[int(len(prefix) / 2):],
                    "src_port": gen_list(fg.gen_port, port_per_rule / 2),
                    "dst_port": gen_list(fg.gen_port, port_per_rule / 2),
                    "src_tag": 0xffffffff,
                    "dst_tag": 0xffffffff,
                }
            )
            print("ACL_RULE", i * ACL_RULES_PER_NSG + j, "/", rule_per_eni)


def gen_route(rp, fg):
    # ROUTE LPM TABLE - OUTBOUND
    for i in range(OUTBOUND_ROUTES_PER_ENI):
        insert_entry(
            rp,
            "DASH_ROUTE_TABLE",
            (FIXED_ENI, FIXED_VNI, fg.gen_prefix()),
            {
                "action_type": "vnet",
                "vnet": fg.pick_vnet_name(),
                "appliance": 0,
                "overlay_ip": fg.gen_ip(),
                "overlay_sip": fg.gen_ip(),
                "overlay_dip": fg.gen_ip(),
                "underlay_sip": fg.gen_ip(),
                "underlay_dip": fg.gen_ip(),
                "metering_bucket": 0,
            }
        )
        print("DASH_ROUTE_TABLE", i, "/", OUTBOUND_ROUTES_PER_ENI)

    # ROUTE RULE TABLE - INBOUND
    for i in range(INBOUND_ROUTES_PER_ENI):
        insert_entry(
            rp,
            "DASH_ROUTE_RULE_TABLE",
            (FIXED_ENI, FIXED_VNI, fg.gen_prefix()),
            {
                "action_type": "decap",
                "priority": 2**32-1,
                "protocol": fg.gen_protocol(),
                "vnet": fg.pick_vnet_name(),
                "pa_validation": True,
                "metering_bucket": 0,
                "region": 0
            }
        )
        print("DASH_ROUTE_RULE_TABLE", i, "/", INBOUND_ROUTES_PER_ENI)


def gen_map(rp, fg):
    for i in range(int(CA_PA_MAPPING / ENI_COUNT)):
        insert_entry(
            rp,
            "DASH_VNET_MAPPING_TABLE",
            (FIXED_ENI, fg.gen_ip()),
            {
                "routing_type": "vnet_encap",
                "underlay_ip": fg.gen_ip(),
                "mac_address": FIXED_MAC,
                "metering_bucket": 0,
                "use_dst_vni": True,
                "use_pl_sip_eni": True,
                "overlay_sip": fg.gen_ip(),
                "overlay_dip": fg.gen_ip(),
            }
        )
        print("DASH_VNET_MAPPING_TABLE", i, "/", CA_PA_MAPPING / ENI_COUNT)


fg = FieldGenerator()
r = redis.Redis(host='localhost', port=6379, db=0)
rp = r.pipeline()

gen_vnets(rp, fg)
if INCLUDE_ACL:
    gen_acl(rp, fg)
gen_route(rp, fg)
gen_map(rp, fg)

rp.execute()

if TABLE_NAME_AS_BINARY:
    print(TABLE_SET)
