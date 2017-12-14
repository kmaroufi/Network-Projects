import sys
from struct import *
import os
from threading import *
from enum import Enum
from packet_model import *
import time


class ConnectionState(Enum):
    waiting_SYN = 1
    waiting_SYN_ACK = 2
    get_data = 3
    waiting_FIN_ACK = 4

class ReaderThread(Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        global receiver_port, data, cs
        # get first packet

        sender_port = 0
        expected_seq_num = 0
        while True:
            tmp = f_read.read(4)
            packet_size = unpack_from("!I", tmp, 0)[0]
            print("received packet with size " + str(packet_size))
            packet_in_bytes = f_read.read(packet_size)
            received_packet_model = PacketModel()
            is_correct = received_packet_model.from_bytes(packet_in_bytes)
            if is_correct is False:
                continue

            if cs == ConnectionState.get_data and received_packet_model.FIN == 1:
                print("last data packet is received")
                expected_seq_num += 1
                print("sending ACK packet")
                sending_packet_model = PacketModel(sender_port=receiver_port, receiver_port=sender_port,
                                                   seq_num=0, ack_num=expected_seq_num, CWR=0, ACK=1,
                                                   SYN=0, FIN=0,
                                                   window_size=1,
                                                   data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()

                print("sending FIN packet")
                sending_packet_model = PacketModel(sender_port=receiver_port, receiver_port=sender_port,
                                                   seq_num=0, ack_num=0, CWR=0, ACK=0,
                                                   SYN=0, FIN=1,
                                                   window_size=1,
                                                   data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
                cs = ConnectionState.waiting_FIN_ACK
                continue

            if cs == ConnectionState.waiting_FIN_ACK:
                if received_packet_model.ACK == 1 and received_packet_model.ack_num == 1:
                    break

            if cs == ConnectionState.waiting_SYN:
                if received_packet_model.SYN == 0:
                    continue
                if received_packet_model.data is not None:
                    continue
                print("sending SYN/ACK packet")
                sender_port = received_packet_model.sender_port
                expected_seq_num = received_packet_model.seq_num + 1
                sending_packet_model = PacketModel(sender_port=receiver_port, receiver_port=sender_port,
                                                   seq_num=0, ack_num=expected_seq_num, CWR=0, ACK=1, SYN=1, FIN=0,
                                                   window_size=1,
                                                   data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
                cs = ConnectionState.waiting_SYN_ACK
                continue

            # get ack for SYN/ACK
            if cs == ConnectionState.waiting_SYN_ACK:
                print("ack for SYN/ACK received")
                if received_packet_model.ACK == 0:
                    continue
                if received_packet_model.data is not None:
                    continue
                cs = ConnectionState.get_data
                expected_seq_num += 1
                continue

            if cs == ConnectionState.get_data:
                if data.get(received_packet_model.seq_num) is None:
                    data[received_packet_model.seq_num] = received_packet_model.data
                while True:
                    if data.get(expected_seq_num) is not None:
                        expected_seq_num += 1
                    else:
                        break
                print("sending ACK packet")
                sending_packet_model = PacketModel(sender_port=receiver_port, receiver_port=sender_port,
                                                   seq_num=0, ack_num=expected_seq_num, CWR=0, ACK=1,
                                                   SYN=0, FIN=0,
                                                   window_size=1,
                                                   data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()

        f = open("received", "wb")
        for item in data.values():
            f.write(item)

        f.flush()
        f.close()

        f_read.close()
        f_write.close()
        os.remove(read_file_path)


receiver_port = sys.argv[1]
# receiver_port = 5678

read_file_path = "../pipes/" + "receiver_" + str(receiver_port) + "_data.pipe"
transmitter_file_path = "../pipes/" + "backwardnet_data.pipe"

os.mkfifo(read_file_path)

f_read = open(read_file_path, 'rb')
print("passed")
f_write = open(transmitter_file_path, 'wb')
print("passed")
data = {}
cs = ConnectionState.waiting_SYN

ReaderThread().start()
