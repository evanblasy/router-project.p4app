/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<32> IP;

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_IPV4         = 0x800;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;

const bit<8> TYPE_ICMP         = 0x1;
const bit<8> TYPE_OSPF         = 0x59;


header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ospf_t {
    bit<8> version;
    bit<8> type;
    ip4Addr_t router_id;
    bit<32> area_id;
    bit<16> chksum;
    bit<16> autype;
    bit<64> auth;
}

header icmp_t {
    bit<8> type;
    bit<8> code;
    bit<16> hdrChecksum;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    ipv4_t            ipv4;
    arp_t             arp;
    icmp_t            icmp;
    ipv4_t            icmp_ipv4;
    ospf_t            ospf;
}

struct metadata { }

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_IPV4: parse_ipv4;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_ICMP: parse_icmp;
            TYPE_OSPF: parse_ospf;
            default: accept;
        }
    }

    state parse_ospf {
        packet.extract(hdr.ospf);
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true,
            { hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    // 0 for IP, 1 for ARP, 2 for sent to CPU
    counter(3, CounterType.packets) packet_counter;
    
    action tally(bit<32> index) {
        packet_counter.count(index);
    }

    action drop() {
        mark_to_drop();
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
    }

    action cpu_meta_encap() {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu() {
        cpu_meta_encap();
        standard_metadata.egress_spec = CPU_PORT;
    }

    action ipv4_forward(macAddr_t dstAddr, port_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action response_to_arp(macAddr_t dstAddr) {
        if (hdr.arp.opcode != ARP_OP_REPLY) {
            hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = dstAddr;

            hdr.arp.dstEth = hdr.arp.srcEth;
            hdr.arp.srcEth = dstAddr;
            ip4Addr_t temp = hdr.arp.srcIP; 
            hdr.arp.srcIP = hdr.arp.dstIP;
            hdr.arp.dstIP = temp;

            hdr.arp.opcode = ARP_OP_REPLY;
        }
    }

    action ttl_zero_response() {
        hdr.icmp.setValid();
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        macAddr_t temp = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = temp;

        ipv4_t old_ipv4 = hdr.ipv4;

        // hdr.icmp_ipv4.setValid();
        // hdr.icmp_ipv4 = old_ipv4;
        hdr.icmp.type = 11;
        hdr.icmp.code = 0;
        hdr.icmp.hdrChecksum = 0;

        hdr.ipv4.protocol = TYPE_ICMP;
        hdr.ipv4.dstAddr = old_ipv4.srcAddr;
        hdr.ipv4.ttl = 64;
        
        hdr.ipv4.totalLen = 52;

        truncate((bit<32>)64);
    }

    table arp_exact {
        key = {
            hdr.arp.dstIP: exact;
        }
        actions = {
            response_to_arp;
            NoAction;
        }
        size = 64;
        default_action = NoAction;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction;
    }

   table fwd_l2 {
        key = {
            hdr.ethernet.dstAddr: exact;
        }
        actions = {
            set_egr;
            set_mgid;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {

        if (standard_metadata.ingress_port == CPU_PORT)
            cpu_meta_decap();

        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            arp_exact.apply();
            tally(1);
            send_to_cpu();
        } else if (hdr.ipv4.isValid()) {
            if(hdr.ipv4.ttl == 1) {
                send_to_cpu();
            } else {
                ipv4_lpm.apply();
            }
            tally(0);
        } else if (hdr.ethernet.isValid()) {
            fwd_l2.apply();
        }

       if (standard_metadata.egress_spec == CPU_PORT) {
           tally(2);
       } 
    }
}

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
                { hdr.ipv4.version,
                  hdr.ipv4.ihl,
                  hdr.ipv4.diffserv,
                  hdr.ipv4.totalLen,
                  hdr.ipv4.identification,
                  hdr.ipv4.flags,
                  hdr.ipv4.fragOffset,
                  hdr.ipv4.ttl,
                  hdr.ipv4.protocol,
                  hdr.ipv4.srcAddr,
                  hdr.ipv4.dstAddr },
                hdr.ipv4.hdrChecksum,
                HashAlgorithm.csum16);

        // update_checksum(
        //     hdr.icmp.isValid(),
        //         { hdr.icmp.type,
        //           hdr.icmp.code },
        //         hdr.icmp.hdrChecksum,
        //         HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.icmp);
        packet.emit(hdr.icmp_ipv4);
        packet.emit(hdr.ospf);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
