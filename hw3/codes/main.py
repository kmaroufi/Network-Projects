import dpkt
from struct import *
import sys

graph = []

nodes = {0}
nodes.remove(0)

network = {}

def extract_lsu(buffer):
    buffer = bytearray(buffer)
    lsa_number = unpack_from("!I", buffer, 0)[0]
    index = 4
    for i in range(lsa_number):
        # extract header
        ls_age = unpack_from("!H", buffer, index)[0]
        index += 3
        ls_type = unpack_from("!B", buffer, index)[0]
        index += 1
        link_state_id = unpack_from("!I", buffer, index)[0]
        index += 4
        advertising_router = unpack_from("!I", buffer, index)[0]
        index += 4
        ls_sequence_number = unpack_from("!I", buffer, index)[0]
        index += 4
        ls_checksum = unpack_from("!H", buffer, index)[0]
        index += 2
        length = unpack_from("!H", buffer, index)[0]
        index += 2
        if ls_type != 1:
            index += length - 20
            continue
        # extract Router-LSA
        index += 2
        links_number = unpack_from("!H", buffer, index)[0]
        index += 2
        # print(ls_age, ls_type, link_state_id, advertising_router, ls_sequence_number, ls_checksum, length, links_number)
        nodes.add(link_state_id)
        for j in range(links_number):
            link_id = unpack_from("!I", buffer, index)[0]
            index += 4
            link_data = unpack_from("!I", buffer, index)[0]
            index += 4
            type = unpack_from("!B", buffer, index)[0]
            index += 1
            tos_number = unpack_from("!B", buffer, index)[0]
            index += 1
            tos_0_metric = unpack_from("!H", buffer, index)[0]
            index += 2
            if network.get(link_id) is None:
                network[link_id] = {0}
                network[link_id].remove(0)
            network[link_id].add(link_state_id)
            # print(tos_number)
            for k in range(tos_number):
                tos = unpack_from("!B", buffer, index)[0]
                index += 2
                tos_metric = unpack_from("!H", buffer, index)[0]
                index += 2

file_path = sys.argv[1]
f_pcap = open(file_path, 'rb')
pcap = dpkt.pcap.Reader(f_pcap)

packets = []
for ts, buf in pcap:
    x = dpkt.ethernet.Ethernet(buf)
    packets += [x]
f_pcap.close()

z = 0
for pack in packets:
    z += 1
    # print(z)
    if pack.type == 2048: #ip
        ip = pack.data
        # print(ip.get_proto(ip.p))
        if ip.p == 89: #ospf
            ospf = ip.data
            # print(ospf.type)
            if ospf.type == 4: #LSU
                lsu = ospf.data
                extract_lsu(lsu)
                # print("---------")
    # print isinstance(x.data, dpkt.ip.IP)
    # if isinstance(x.data, dpkt.ip.IP):
    #     ip = x.data
    #     print type(ip.data)
    # if x.type == 2048:
        # print dpkt.ip.IP(x.data)
        # print x.data
    # ip = x.data

    # ip.type
    # print dpkt.ip.IP(ip)
    # x = dpkt.ip.IP(buf)
    # print(x.type, x.get_type(x.type))
    # print x._typesw.values()

# print(len(nodes))
# print(sorted(nodes))
# print(len(network))
# print(network)
# print("SDF")

matrix = [[0 for i in range(len(nodes))] for j in range(len(nodes))]
set_nodes = nodes
nodes = sorted(nodes)
index_nodes = {}
for i in range(len(nodes)):
    index_nodes[nodes[i]] = i

for key, value in network.items():
    for ip1 in value:
        for ip2 in value:
            if ip1 == ip2:
                continue
            matrix[index_nodes[ip1]][index_nodes[ip2]] = 1
            matrix[index_nodes[ip2]][index_nodes[ip1]] = 1
    if set_nodes.__contains__(key):
        for ip1 in value:
            if ip1 == key:
                continue
            matrix[index_nodes[key]][index_nodes[ip1]] = 1
            matrix[index_nodes[ip1]][index_nodes[key]] = 1


for i in range(len(nodes)):
    for j in range(len(nodes)):
        print(matrix[i][j], end="")
        if j + 1 != len(nodes):
            print(end=",")
    print("")

