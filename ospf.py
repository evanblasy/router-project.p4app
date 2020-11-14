from scapy.fields import IntField, ByteEnumField, FieldLenField, PacketListField, IPField, LongField, ShortField, ByteField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP

TYPE_OSPF = 0x59
TYPE_OSPF_HELLO = 0x1
TYPE_OSPF_LSU = 0x4

class OSPF(Packet):
    name = "OSPF"
    fields_desc = [ ByteField("version", 2),
                    ByteEnumField("type",1 , {1: "hello", 4: "LSU"}),
                    ShortField("len", 24),
                    IPField("router_id", None),
                    IPField("area_id", None),
                    ShortField("chksum", 0),
                    ShortField("autype", 0),
                    LongField("auth", 0)
                    ]

class OSPF_hello(Packet):
    name = "OSPF_hello"
    fields_desc = [ IPField("net_mask", None),
                    ShortField("hello_int", None),
                    ShortField("padding", 0)
                    ]

class LSU(Packet):
    fields_desc = [ IPField("subnet", None),
                    IPField("mask", None),
                    IntField("router_id", None)]

class OSPF_LSU(Packet):
    name = "OSPF_LSU"
    fields_desc = [ ShortField("seq", 0),
                    ShortField("ttl", 64),
                    FieldLenField("adverts", 0, count_of='lsu_ads'),
                    PacketListField('lsu_ads', [], LSU, count_from = lambda a : (a.adverts))
                    ]


bind_layers(IP, OSPF, proto=TYPE_OSPF)
bind_layers(OSPF, OSPF_hello, type=TYPE_OSPF_HELLO)
bind_layers(OSPF, OSPF_hello, type=TYPE_OSPF_LSU)
