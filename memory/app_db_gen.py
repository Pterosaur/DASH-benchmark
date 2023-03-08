#!/bin/python3

import os
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import random
import redis
import collections
import ipaddress
import uuid
import struct
import binascii
import math
import zlib
import app_db_pb2
# import mysql.connector

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
FIXED_PREFIES_PER_TAG = 8000
FIXED_PREFIXES_PER_RULE = 8000

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
# SAVE_PREFIX_AS_BINARY = True
TO_BINARY = True
KEY_AS_BINARY = False
HASH_KEY_AS_BINARY = False
MOVE_HASH_TO_ONE = True
USE_TAG = True
IS_IPV4 = False
TABLE_SET = collections.defaultdict(dict)
USE_HASH_TABLE = True
GZIP_VALUE = False
PROTOBUF_VALUE = True
KEY_ONLY = False
RANDOM_GEN = True
TABLE_SET_REVERSE = {}
DUMP_TO_MYSQL = False

SAMPLE_KEYS = []


# class MySQL(object):
#     def __init__(self):
#         self.con = mysql.connector.connect(database="app_db")
#         self.cursor = self.con.cursor()
#         self.available_table = set()

#     def create_table(self, table_name, attribute_name):
#         if table_name in self.available_table:
#             return
#         self.cursor = self.con.cursor()
#         self.cursor.execute("SHOW TABLES LIKE '{}';".format(table_name))
#         if self.cursor.fetchone() is not None:
#             self.available_table.add(table_name)
#             return
#         create_table_format = b"CREATE TABLE %b (entry_key VARCHAR(255), %b PRIMARY KEY (entry_key));"
#         attribute_string = b""
#         for attr in attribute_name:
#             attribute_string += attr + b" MEDIUMBLOB, "
#         create_table = create_table_format % (table_name.encode("utf-8"), attribute_string)
#         print(create_table)
#         self.cursor.execute(create_table)

#     def insert_entry(self, table_name, entry_key, attribute_value):
#         if table_name not in self.available_table:
#             self.create_table(table_name, attribute_value.keys())
#         insert_format = [b"INSERT INTO ","", b" (entry_key, ", "", b") VALUES (%s, ", b"", b") ON DUPLICATE KEY UPDATE;"]
#         attribute_names = b", ".join(attribute_value.keys())
#         value_string = b", ".join([b"%s"] * len(attribute_value))
#         insert_format[1] = table_name.encode("utf-8")
#         insert_format[3] = attribute_names
#         insert_format[5] = value_string
#         insert_format = b"".join(insert_format)
#         print(insert_format)
#         self.cursor.execute(insert_format, [entry_key] + list(attribute_value.values()))

#     def commit(self):
#         self.con.commit()

#     def close(self):
#         self.cursor.close()
#         self.con.close()


# sql = MySQL()


class Protocol(object):
    def __init__(self, protocol) -> None:
        self.protocol = protocol

    def __str__(self):
        return str(self.protocol)

    def to_binary(self):
        return struct.pack("B", self.protocol)

    def to_pb(self):
        return self.protocol

class Port(object):
    def __init__(self, port) -> None:
        self.port = port

    def __str__(self):
        return str(self.port)

    def to_binary(self):
        return struct.pack("H", self.port)

    def to_pb(self):
        return self.port

class MAC(object):
    def __init__(self, mac) -> None:
        self.mac = mac

    def __str__(self):
        return str(self.mac)

    def to_binary(self):
        return binascii.unhexlify(self.mac.replace(":", ""))

    def to_pb(self):
        return self.to_binary()


def value_to_pb(value):
    if False:
        pass
    # if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
    #     return value.network_address.packed + struct.pack("B", value.prefixlen)
    elif isinstance(value, ipaddress.IPv4Network):
        prefix = app_db_pb2.IpPrefix()
        prefix.ip.ipv4 = value.network_address.packed
        prefix.prefix_len = value.prefixlen
        return prefix
    elif isinstance(value, ipaddress.IPv6Network):
        prefix = app_db_pb2.IpPrefix()
        prefix.ip.ipv6 = value.network_address.packed
        prefix.prefix_len = value.prefixlen
        return prefix
    elif isinstance(value, ipaddress.IPv4Address):
        ip = app_db_pb2.IpAddress()
        ip.ipv4 = value.packed
        return ip
    elif isinstance(value, ipaddress.IPv6Address):
        ip = app_db_pb2.IpAddress()
        ip.ipv6 = value.packed
        return ip
    elif isinstance(value, (Protocol, Port, MAC)):
        return value.to_pb()
    elif isinstance(value, uuid.UUID):
        return str(value)
    else:
        return value


def values_to_pb(table, values):
    if table == "DASH_VNET_TABLE":
        entry = app_db_pb2.Vnet()
    elif table == "DASH_VNET_MAPPING_TABLE":
        entry = app_db_pb2.VnetMapping()
    elif table == "DASH_PREFIX_TAG_TABLE":
        entry = app_db_pb2.PrefixTag()
    elif table == "DASH_ENI_TABLE":
        entry = app_db_pb2.Eni()
    elif table == "DASH_ACL_RULE_TABLE":
        entry = app_db_pb2.AclRule()
    elif table == "DASH_ROUTE_TABLE":
        entry = app_db_pb2.Route()
    elif table == "DASH_ROUTE_RULE_TABLE":
        entry = app_db_pb2.RouteRule()
    else:
        return None
    for k, v in values.items():
        if hasattr(v, "__iter__") and not isinstance(v, (str, ipaddress.IPv4Network, ipaddress.IPv6Network)):
            for i in v:
                getattr(entry, k).append(value_to_pb(i))
        else:
            field = getattr(entry, k)
            if hasattr(field, "CopyFrom"):
                field.CopyFrom(value_to_pb(v))
            else:
                setattr(entry, k, value_to_pb(v))
    return entry.SerializeToString()


def to_binary(v):
    if isinstance(v, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return v.network_address.packed + struct.pack("B", v.prefixlen)
    elif isinstance(v, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return v.packed
    elif isinstance(v, (Protocol, Port, MAC)):
        return v.to_binary()
    elif isinstance(v, bytes):
        return v
    else:
        return str(v).encode("utf-8") + b":"


def insert_entry(rp, table, key, values):
    useful_size = 0
    if PROTOBUF_VALUE:
        field_name = "0"
        field_value = values_to_pb(table, values)
    for k, v in values.items():
        if isinstance(v, list):
            if TO_BINARY:
                values[k] = b"".join([to_binary(x) for x in v])
            else:
                values[k] = ",".join([str(x) for x in v])
        else:
            if TO_BINARY:
                values[k] = to_binary(v)
            else:
                values[k] = str(v)
    if KEY_AS_BINARY:
        if table not in TABLE_SET:
            TABLE_SET[table]["table_id"] = len(TABLE_SET)
            TABLE_SET_REVERSE[len(TABLE_SET_REVERSE)] = table
        table_id = struct.pack("B", TABLE_SET[table]["table_id"])
        if hasattr(key, "__iter__") and not isinstance(key, str):
            # key = b"".join([to_binary(x) for x in key])
            bkey = b""
            for i in range(len(key)):
                if isinstance(key[i], str):
                    bkey += key[i].encode("utf-8")
                    if i != len(key) - 1:
                        bkey += b":" # separator
                else:
                    bkey += to_binary(key[i])
            key = bkey
        key = table_id + b":" + to_binary(key)
    else:
        if hasattr(key, "__iter__") and not isinstance(key, str):
            key = ":".join([str(x) for x in key])
        key = table + ":" + str(key)
    if HASH_KEY_AS_BINARY:
        bvalues = {}
        hash_key_map = {}
        for k, v in values.items():
            if k not in hash_key_map:
                hash_key_map[k] = len(hash_key_map)
            bvalues[struct.pack("B", hash_key_map[k])] = v
        values = bvalues
    if KEY_ONLY:
        values = {b"Placeholder": b"Placeholder"}
        value = b"Placeholder"
    if GZIP_VALUE:
        value = zlib.compress(value)
    if MOVE_HASH_TO_ONE:
        hash_key = b"\xff" * int(math.ceil(len(values) / 8))
        hash_value = b"".join(values.values())
        value = hash_key + hash_value
        values = {hash_key: hash_value}
    if PROTOBUF_VALUE:
        value = field_value
        values = {field_name: field_value}
    if USE_HASH_TABLE:
        rp.hset(key, mapping=values)
        # if DUMP_TO_MYSQL:
        #     sql.insert_entry(table, key.replace(table + ":", ""), values)
        useful_size = len(key)
        for k, v in values.items():
            useful_size += len(k) + len(v)
    else:
        rp.set(key, value)
        useful_size = len(key) + len(value)
        pass
    return key, useful_size


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
        return str(self.vni)

    def gen_prefix(self, key=None, is_ipv4=IS_IPV4):
        if RANDOM_GEN:
            if is_ipv4:
                self.prefix_id[key] = random.randint(0, 2 ** 32 - 1)
            else:
                self.prefix_id[key] = random.randint(0, 2 ** 126 - 1)
        else:
            self.prefix_id[key] += 1
        if is_ipv4:
            prefix = ipaddress.IPv4Network(self.prefix_id[key], strict=False)
        else:
            prefix = ipaddress.IPv6Network(self.prefix_id[key], strict=False)
        return prefix

    def gen_ip(self, key=None, is_ipv4=IS_IPV4):
        if RANDOM_GEN:
            if is_ipv4:
                self.address_id[key] = random.randint(0, 2 ** 32 - 1)
            else:
                self.address_id[key] = random.randint(0, 2 ** 126 - 1)
        else:
            self.address_id[key] += 1
        if is_ipv4:
            address = ipaddress.IPv4Address(self.address_id[key])
        else:
            address = ipaddress.IPv6Address(self.address_id[key])
        return address

    def gen_port(self, key=None):
        self.port_id[key] += 1
        return Port(self.port_id[key] % 65536)

    def gen_port_range(self, key=None):
        start = self.gen_port(key)
        end = self.gen_port(key)
        if start < end:
            return (start, end)
        else:
            return (end, start)

    def gen_protocol(self, key=None):
        self.protocol_id[key] += 1
        return Protocol(self.protocol_id[key] % 256)

    def gen_guid(self):
        return uuid.uuid4()

    def gen_acl_group_id(self):
        self.acl_group_id += 1
        return self.acl_group_id

    def pick_acl_group_id(self):
        return random.randint(1, self.acl_group_id)


def gen_list(gen_func, count=10, *args, **kwargs):
    # if count <= 1:
    #     count = 1
    return [gen_func(*args, **kwargs) for i in range(int(count))]


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
            (MAC(FIXED_ENI), fg.pick_acl_group_id()),
            {
                "acl_group_id": fg.pick_acl_group_id(),
            }
        )
        insert_entry(
            rp,
            "DASH_ACL_OUT_TABLE",
            (MAC(FIXED_ENI), fg.pick_acl_group_id()),
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
                    "src_tag": ["0xffffffff"],
                    "dst_tag": ["0xffffffff"],
                }
            )
            print("ACL_RULE", i * ACL_RULES_PER_NSG + j, "/", rule_per_eni)


def gen_route(rp, fg):
    # ROUTE LPM TABLE - OUTBOUND
    for i in range(OUTBOUND_ROUTES_PER_ENI):
        insert_entry(
            rp,
            "DASH_ROUTE_TABLE",
            (MAC(FIXED_ENI), FIXED_VNI, fg.gen_prefix()),
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
            (MAC(FIXED_ENI), FIXED_VNI, fg.gen_prefix()),
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
            (fg.pick_vnet_name(), fg.gen_ip()),
            {
                "routing_type": "vnet_encap",
                "underlay_ip": fg.gen_ip(),
                "mac_address": MAC(FIXED_MAC),
                "metering_bucket": 0,
                "use_dst_vni": True,
                "use_pl_sip_eni": True,
                "overlay_sip": fg.gen_ip(),
                "overlay_dip": fg.gen_ip(),
            }
        )
        print("DASH_VNET_MAPPING_TABLE", i, "/", CA_PA_MAPPING / ENI_COUNT)

def gen_sample(rp, fg):
    key = insert_entry(
        rp,
        "DASH_VNET_TABLE",
        fg.gen_vnet_name(),
        {
            "vni": fg.gen_vni(),
            "guid": fg.gen_guid(),
            "address_space": gen_list(fg.gen_prefix),
            "peer_list": gen_list(fg.pick_vnet_name),
        })
    SAMPLE_KEYS.append(key)

    key = insert_entry(
        rp,
        "DASH_VNET_MAPPING_TABLE",
        (fg.gen_vnet_name(), fg.gen_ip()),
        {
            "routing_type": "vnet_encap",
            "underlay_ip": fg.gen_ip(),
            "mac_address": MAC(FIXED_MAC),
            "metering_bucket": 0,
            "use_dst_vni": True,
            "use_pl_sip_eni": True,
            "overlay_sip": fg.gen_ip(),
            "overlay_dip": fg.gen_ip(),
        }
    )
    SAMPLE_KEYS.append(key)

    for prefix_count in [0, 10, 100, 200, 1000, 2000, 8000]:
        key = insert_entry(
            rp,
            "DASH_PREFIX_TAG_TABLE",
            ("prefix", prefix_count),
            {
                "prefix_list": gen_list(fg.gen_prefix, prefix_count),
            }
        )
        SAMPLE_KEYS.append(key)

    key = insert_entry(
        rp,
        "DASH_ENI_TABLE",
        MAC(FIXED_MAC),
        {
            "eni_id": MAC(FIXED_MAC),
            "mac_address": MAC(FIXED_MAC),
            "qos": "qos_name",
            "underlay_ip": fg.gen_ip(),
            "admin_state": "disabled",
            "vnet": fg.gen_vnet_name(),
            "pl_sip_encoding": fg.gen_prefix(),
            "pl_underlay_sip": fg.gen_ip(),
        }
    )
    SAMPLE_KEYS.append(key)

    for prefix_count in [0, 10, 100, 200, 1000, 2000, 8000]:
        key = insert_entry(
            rp,
            "DASH_ACL_RULE_TABLE",
            ("group_id", prefix_count),
            {
                "priority": 2**32-1,
                "action": "allow",
                "terminating": True,
                "protocol": gen_list(fg.gen_protocol, 255),
                "src_addr": gen_list(fg.gen_prefix, prefix_count/2),
                "dst_addr": gen_list(fg.gen_prefix, prefix_count/2),
                "src_port": gen_list(fg.gen_port, 5),
                "dst_port": gen_list(fg.gen_port, 5),
                "src_tag": ["prefix" + str(prefix_count)],
                "dst_tag": ["prefix" + str(prefix_count)],
            }
        )
        SAMPLE_KEYS.append(key)

    key = insert_entry(
        rp,
        "DASH_ROUTE_TABLE",
        (MAC(FIXED_ENI), FIXED_VNI, fg.gen_prefix()),
        {
            "action_type": "vnet",
            "vnet": fg.gen_vnet_name(),
            "appliance": 0,
            "overlay_ip": fg.gen_ip(),
            "overlay_sip": fg.gen_ip(),
            "overlay_dip": fg.gen_ip(),
            "underlay_sip": fg.gen_ip(),
            "underlay_dip": fg.gen_ip(),
            "metering_bucket": 0,
        }
    )
    SAMPLE_KEYS.append(key)

    key = insert_entry(
        rp,
        "DASH_ROUTE_RULE_TABLE",
        (MAC(FIXED_ENI), FIXED_VNI, fg.gen_prefix()),
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
    SAMPLE_KEYS.append(key)

fg = FieldGenerator()

r = redis.Redis(host='localhost', port=6379, db=0)
rp = r.pipeline()

# gen_vnets(rp, fg)
# if INCLUDE_ACL:
#     gen_acl(rp, fg)
# gen_route(rp, fg)
# gen_map(rp, fg)

gen_sample(rp, fg)

rp.execute()

def report_memory_usage(r):
    if KEY_AS_BINARY:
        print(TABLE_SET)
    # Total memory
    print("Used memory human: ", r.info("memory")["used_memory_human"])
    for key, useful_size in SAMPLE_KEYS:
        if KEY_AS_BINARY:
            table_id = struct.unpack("B", key[0:1])[0]
            table_name = TABLE_SET_REVERSE[table_id]
            print("Table ", table_name, " Key ", key ," type ", r.object("encoding", key), " entry size ", r.memory_usage(key, 0), " useful size ", useful_size)
        else:
            print("Key ", key ," type ", r.object("encoding", key), " entry size ", r.memory_usage(key, 0), " useful size ", useful_size)


report_memory_usage(r)

# if DUMP_TO_MYSQL:
#     sql.commit()
#     sql.close()
