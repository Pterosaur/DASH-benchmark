
# Original

1 NSG


## Total Memory

```
127.0.0.1:6379> info memory
# Memory
used_memory:4038654696
used_memory_human:3.76G
used_memory_rss:3745890304
used_memory_rss_human:3.49G
used_memory_peak:8212579328
used_memory_peak_human:7.65G
used_memory_peak_perc:49.18%
used_memory_overhead:16150240
used_memory_startup:862232
used_memory_dataset:4022504456
used_memory_dataset_perc:99.62%
allocator_allocated:4039048584
allocator_active:4121481216
allocator_resident:4155416576
total_system_memory:67435036672
total_system_memory_human:62.80G
used_memory_lua:31744
used_memory_vm_eval:31744
used_memory_lua_human:31.00K
used_memory_scripts_eval:0
number_of_cached_scripts:0
number_of_functions:0
number_of_libraries:0
used_memory_vm_functions:32768
used_memory_vm_total:64512
used_memory_vm_total_human:63.00K
used_memory_functions:184
used_memory_scripts:184
used_memory_scripts_human:184B
maxmemory:0
maxmemory_human:0B
maxmemory_policy:noeviction
allocator_frag_ratio:1.02
allocator_frag_bytes:82432632
allocator_rss_ratio:1.01
allocator_rss_bytes:33935360
rss_overhead_ratio:0.90
rss_overhead_bytes:-409526272
mem_fragmentation_ratio:0.93
mem_fragmentation_bytes:-292743720
mem_not_counted_for_evict:0
mem_replication_backlog:0
mem_total_replication_buffers:0
mem_clients_slaves:0
mem_clients_normal:1800
mem_cluster_links:0
mem_aof_buffer:0
mem_allocator:jemalloc-5.2.1
active_defrag_running:0
lazyfree_pending_objects:0
lazyfreed_objects:0

```

## VNET

### DASH_VNET_TABLE

```
127.0.0.1:6379> hgetall "DASH_VNET_TABLE:vnet1303"
1) "peer_list"
2) "vnet798,vnet1117,vnet1283,vnet1028,vnet587,vnet567,vnet561,vnet330,vnet124,vnet1243"
3) "address_space"
4) "0000:0000:0000:0000:0000:0000:0000:196f/128 ... 0000:0000:0000:0000:0000:0000:0000:1978/128" // 10
5) "vni"
6) "0"
7) "guid"
8) "d10fc1df-d96d-4d57-8ed0-b6a59260eb60"
```

entry - 1024
896B / entry

## DASH ACL

### DASH_ACL_GROUP_TABLE

peanut

### DASH_ACL_RULE_TABLE

```
127.0.0.1:6379> hgetall "DASH_ACL_RULE_TABLE:5:2787"
 1) "terminating"
 2) "True"
 3) "protocol"
 4) "30 ... ,28" // 255
 5) "src_addr"
 6) "0000:0000:0000:0000:0000:0000:0000:2801/128 ... // 4000
 7) "dst_addr"
 8) "0000:0000:0000:0000:0000:0000:0000:2801/128 ... // 4000
 9) "src_port"
 10) "27871,27872,27873,27874,27875" // 5
 11) "action"
 12) "allow"
 13) "dst_port"
 14) "27876,27877,27878,27879,27880"
 15) "priority"
 16) "4294967295"
```

entry - 10000
631360B / entry

### DASH_PREFIX_TAG_TABLE

```
127.0.0.1:6379> hgetall "DASH_PREFIX_TAG_TABLE:7"
1) "prefix_list"
2) "0000:0000:0000:0000:0000:0000:0001:02c1/128,... // 8000
```

## Route

### DASH_ROUTE_TABLE

```
127.0.0.1:6379> hgetall "DASH_ROUTE_TABLE:F4939FEFC47E:2000:::cd52/128"
 1) "action_type"
 2) "vnet"
 3) "vnet"
 4) "vnet9"
 5) "appliance"
 6) "0"
 7) "overlay_ip"
 8) "0.3.56.162"
 9) "overlay_sip"
10) "0.3.56.163"
11) "overlay_dip"
12) "0.3.56.164"
13) "underlay_sip"
14) "0.3.56.165"
15) "underlay_dip"
16) "0.3.56.166"
17) "metering_bucket"
18) "0"
```

entry - 100000
320B / entry

### DASH_ROUTE_RULE_TABLE

```
127.0.0.1:6379> hgetall "DASH_ROUTE_RULE_TABLE:F4939FEFC47E:2000:::1:b6de/128"
 1) "action_type"
 2) "decap"
 3) "priority"
 4) "4294967295"
 5) "protocol"
 6) "202"
 7) "vnet"
 8) "vnet1728"
 9) "pa_validation"
10) "True"
11) "metering_bucket"
12) "0"
13) "region"
14) "0"
```

entry - 10000
224B / entry

## MAPPING

```
127.0.0.1:6379> hgetall "DASH_VNET_MAPPING_TABLE:F4939FEFC47E:0.12.156.89"
 1) "routing_type"
 2) "vnet_encap"
 3) "underlay_ip"
 4) "0.12.156.90"
 5) "mac_address"
 6) "F9:22:83:99:22:A2"
 7) "metering_bucket"
 8) "0"
 9) "use_dst_vni"
10) "True"
11) "use_pl_sip_eni"
12) "True"
13) "overlay_sip"
14) "0.12.156.91"
15) "overlay_dip"
16) "0.12.156.92"
```

entry - 156250
320B / entry


#### binary prefix

264358B / entry
1.62G

#### only ACL with prefix

1.54G

#### no prefix

2240B
103M

#### only ACL with binary prefix

#### only ACL without prefix

USED 16MB
RSS  65MB

#### No ACL

85MB

### TAG prefix

text prefix
116MB
binary prefix
108MB

#### target and rule prefix

120MB

table name as binary
115MB

table as text
150M

### Target Memory usage
128MB