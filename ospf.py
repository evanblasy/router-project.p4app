from scapy.fields import BitField, ByteEnumField, FieldLenField, PacketListField, IPField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP

TYPE_OSPF = 0x59
TYPE_OSPF_HELLO = 0x1
TYPE_OSPF_LSU = 0x4

class OSPF(Packet):
    name = "OSPF"
    fields_desc = [ BitField("version", 2, 8),
                    ByteEnumField("type",1 , {1: "hello", 4: "LSU"}),
                    BitField("len", 24, 16),
                    BitField("router_id", 0, 32),
                    BitField("area_id", 0, 32),
                    BitField("chksum", 0, 16),
                    BitField("autype", 0, 16),
                    BitField("auth", 0, 64)
                    ]

class OSPF_hello(Packet):
    name = "OSPF_hello"
    fields_desc = [ BitField("net_mask", 0, 32),
                    BitField("hello_int", 0, 16),
                    BitField("padding", 0, 16)
                    ]

class LSU(Packet):
    fields_desc = [ IPField("subnet", None),
                    IPField("mask", None),
                    IPField("router_id", None)]

class OSPF_LSU(Packet):
    name = "OSPF_LSU"
    fields_desc = [ BitField("seq", 0, 16),
                    BitField("ttl", 64, 16),
                    FieldLenField("adverts", 0, count_of='lsu_ads'),
                    PacketListField('lsu_ads', [], LSU, count_from = lambda a : (a.adverts))
                    ]


bind_layers(IP, OSPF, type=TYPE_OSPF)
bind_layers(OSPF, OSPF_hello, type=TYPE_OSPF_HELLO)
bind_layers(OSPF, OSPF_hello, type=TYPE_OSPF_LSU)
