from struct import *
from random import *

class PacketModel():
    def __init__(self, sender_port=0, receiver_port=0, seq_num=0, ack_num=0, CWR=0, ACK=0, SYN=0, FIN=0, window_size=0,
                 data=None):
        self.sender_port = sender_port
        self.receiver_port = receiver_port
        self.seq_num = seq_num
        self.ack_num = ack_num
        self.CWR = CWR
        self.ACK = ACK
        self.SYN = SYN
        self.FIN = FIN
        self.window_size = window_size
        self.check_sum = 0
        self.data = data

    def to_bytes(self):
        buffer = bytearray(2000)
        pack_into('!H', buffer, 0, self.sender_port)  # sender port
        pack_into('!H', buffer, 2, self.receiver_port)  # receiver port
        pack_into('!I', buffer, 4, self.seq_num)  # Sequence number
        pack_into('!I', buffer, 8, self.ack_num)  # Acknowledgment number (if ACK set)
        pack_into('!B', buffer, 12, 5 << 4)  # Data offset
        flags = (self.CWR << 7) ^ (self.ACK << 4) ^ (self.SYN << 1) ^ self.FIN
        pack_into('!B', buffer, 13, flags)  # flags
        pack_into('!H', buffer, 14, self.window_size)  # window size
        pack_into('!H', buffer, 16, 0)  # checksum
        pack_into('!H', buffer, 18, 0)  # Urgent pointer (if URG set)

        index = 20

        if self.data is not None:
            for byte in self.data:
                pack_into('!B', buffer, index, byte)  # add data
                index += 1

        i = len(buffer) - 1
        while i >= index:
            del buffer[i]
            i -= 1
        # print(buffer)

        self.check_sum = self.calc_checksum(buffer)
        pack_into('!H', buffer, 16, self.check_sum)  # checksum

        size = bytearray(4)
        pack_into("!I", size, 0, len(buffer))

        self.print_packet()

        return size, buffer

    def from_bytes(self, packet):
        # first checking check sum for make sure that packet has been arrived correctly
        # self.check_sum = unpack_from('!H', packet, 16)[0]  # checksum
        # pack_into('!H', packet, 16, 0)  # checksum
        packet = bytearray(packet)
        sum = self.calc_checksum(packet)
        if sum != 0:
            # print("checksum loss")
            return False
        else:
            pass
            # print("checksum true")

        self.sender_port = unpack_from('!H', packet, 0)[0]  # sender port
        self.receiver_port = unpack_from('!H', packet, 2)[0]  # receiver port
        self.seq_num = unpack_from('!I', packet, 4)[0]  # Sequence number
        self.ack_num = unpack_from('!I', packet, 8)[0]  # Acknowledgment number (if ACK set)
        flags = unpack_from('!B', packet, 13)[0]  # flags
        self.CWR = (flags >> 7) & 1
        self.ACK = (flags >> 4) & 1
        self.SYN = (flags >> 1) & 1
        self.FIN = flags & 1
        self.window_size = unpack_from('!H', packet, 14)[0]  # window size
        self.check_sum = unpack_from('!H', packet, 16)[0]  # checksum


        if len(packet) > 20:
            self.data = bytearray(0)
            for i in range(20, len(packet)):
                self.data.append(unpack_from('!B', packet, i)[0])  # TODO

        self.print_packet()

        return True

    def calc_checksum(self, packet):
        sum = 0
        pop_the_last = False
        if len(packet) % 2 == 1:
            pop_the_last = True
            packet.append(0)
        for i in range(0, len(packet), 2):
            a = unpack_from('!H', packet, i)[0]
            sum += a
            carry = sum >> 16
            sum += carry
            sum &= 65535

        if pop_the_last:
            packet.pop()
        # print("b")
        # print(sum)
        sum = ~sum
        # print(sum)
        sum &= 65535
        # print(sum)
        # print("b")
        return sum

    def print_packet(self):
        pass
        # print(self.sender_port, self.receiver_port, self.seq_num, self.ack_num, self.CWR, self.ACK, self.SYN, self.FIN,
        #       self.window_size, self.check_sum, len(self.data) if self.data is not None else None)


def data_generator():
    length = 20000
    data = bytearray(length)
    for i in range(length):
        pack_into("!B", data, i, randint(1, 255))
    return data