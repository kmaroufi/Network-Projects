from code.tortor.packet import *
from run import KEY_PAIRS
import rsa, math


def header_from_bytes_test():
    mbytes = b"1234aaaabbbbccccddddeeee"
    h = Header.from_bytes(mbytes, None)

    print(h.length)
    print(h.hops)


def header_to_bytes_test():
    mbytes = b"1234aaaabbbbccccddddeeee"
    h = Header.from_bytes(mbytes, None)

    print(h.length)
    print(h.hops)

    print(h.to_bytes(None))


def data_packet_body_from_bytes_test():
    mbytes = b"12349876bbbbccccddddeeee"
    body = DataPacketBody.from_bytes(mbytes)

    print(body.dest_pk)
    print(body.src_pk)
    print(body.data)


def data_packet_body_to_bytes_test():
    mbytes = b"12349876bbbbccccddddeeee"
    body = DataPacketBody.from_bytes(mbytes)

    print(body.dest_pk)
    print(body.src_pk)
    print(body.data)

    print(body.to_bytes())


def register_packet_body_from_bytes_test():
    mbytes = b"1234aaaabbbbccccddddeeeeqqqq"
    body = RegisterPacketBody.from_bytes(mbytes)

    print(body.src_pk)
    print(body.return_hops)
    print(body.challenge)


def register_packet_body_to_bytes_test():
    mbytes = b"1234aaaabbbbccccddddeeeeqqqq"
    body = RegisterPacketBody.from_bytes(mbytes)

    print(body.src_pk)
    print(body.return_hops)
    print(body.challenge)

    print(body.to_bytes())


def packet_from_bytes_test():
    header_bytes = b"1234" + rsa.encrypt(b"aaaabbbbccccddddeeee", KEY_PAIRS[0][0])
    body_bytes = rsa.encrypt(b"12349876bbbbccccddddeeee", KEY_PAIRS[0][0])
    packet = Packet.from_bytes(header_bytes + body_bytes, KEY_PAIRS[0][1])

    print(packet)


def packet_to_bytes_test():
    pass

def s():
    rsa.decrypt(b"fddd", KEY_PAIRS[0][1])


# header_from_bytes_test()
# header_to_bytes_test()
# data_packet_body_from_bytes_test()
# data_packet_body_to_bytes_test()
# register_packet_body_from_bytes_test()
# register_packet_body_to_bytes_test()
packet_from_bytes_test()
# a = [1,2]
# print(a[1:5])
