import sys
from struct import *
from random import *
from threading import *
from enum import Enum
from packet_model import *
import os
import math
import time


class ConnectionState(Enum):
    sending_SYN = 1
    waiting_SYN_ACK = 2
    slow_start = 3
    congestion_avoidance = 4
    fast_recovery = 5
    sending_FIN = 6
    waiting_FIN_ACK = 7
    waiting_FIN = 8
    is_finished = 9


class ReaderThread(Thread):

    def __init__(self):
        super().__init__()

    def run(self):
        global timer, timeout, cwnd, data_array, data, first_data_packet_seq_num, \
            min_seq_num, max_seq_num, ssthresh, rtt, cs, f_write, f_read, f_time, dup, lock

        pre_min_seq_num = 0
        pre_max_seq_num = 0

        while True:

            lock.acquire()
            print("cwnd" + str(cwnd))
            if cs == ConnectionState.sending_SYN:
                print("sending SYN packet")
                sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                   seq_num=min_seq_num,
                                                   ack_num=0, CWR=0, ACK=0, SYN=1, FIN=0, window_size=cwnd, data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
                timer = 2 * rtt
                timeout = 2 * rtt
                cs = ConnectionState.waiting_SYN_ACK
            lock.release()

            tmp = f_read.read(4)
            packet_size = unpack_from("!I", tmp, 0)[0]
            print("received ACK packet with size " + str(packet_size))
            packet_in_bytes = f_read.read(packet_size)
            received_packet_model = PacketModel()
            is_correct = received_packet_model.from_bytes(packet_in_bytes)
            if is_correct is False:
                continue

            lock.acquire()
            if first_data_packet_seq_num + len(data) == received_packet_model.ack_num:
                print("sending FIN")
                rtt = math.ceil((1 - 0.125) + 0.125 * (timeout - timer))
                timer = 2 * rtt
                timeout = 2 * rtt
                min_seq_num = received_packet_model.ack_num
                max_seq_num = min_seq_num
                sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                   seq_num=min_seq_num,
                                                   ack_num=0, CWR=0, ACK=0, SYN=0, FIN=1,
                                                   window_size=1, data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
                cs = ConnectionState.waiting_FIN_ACK
                lock.release()
                continue

            if cs == ConnectionState.waiting_FIN_ACK:
                print("enter in ConnectionState.waiting_FIN_ACK")
                if received_packet_model.ack_num != min_seq_num + 1:
                    print(received_packet_model.ack_num, min_seq_num + 1)
                    print("ConnectionState.waiting_FIN_ACK problem")
                    continue
                cs = ConnectionState.waiting_FIN
                lock.release()
                continue

            if cs == ConnectionState.waiting_FIN:
                print("enter in ConnectionState.waiting_FIN")
                if received_packet_model.FIN != 1:
                    print("ConnectionState.waiting_FIN problem")
                    continue
                min_seq_num += 1
                max_seq_num += 1
                sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                   seq_num=0, ack_num=1, CWR=0, ACK=1, SYN=0, FIN=0,
                                                   window_size=1, data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
                timer = 2 * rtt
                timeout = 2 * rtt
                break

            if cs == ConnectionState.waiting_SYN_ACK:
                print("sending ack for SYN/ACK packet")
                if received_packet_model.ack_num != min_seq_num + 1:
                    lock.release()
                    continue
                min_seq_num += 1
                max_seq_num += 1
                sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                   seq_num=min_seq_num, ack_num=0, CWR=0, ACK=1, SYN=0, FIN=0,
                                                   window_size=cwnd, data=None)
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
                timer = 2 * rtt
                timeout = 2 * rtt

                print("sending first data packet")
                min_seq_num += 1
                max_seq_num += 1
                sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                   seq_num=min_seq_num, ack_num=0, CWR=0, ACK=0, SYN=0, FIN=0,
                                                   window_size=cwnd, data=data[min_seq_num])
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
                timer = 2 * rtt
                timeout = 2 * rtt

                cs = ConnectionState.slow_start
                lock.release()
                continue

            if cs == ConnectionState.slow_start:
                print("slow start")
                if received_packet_model.ack_num >= min_seq_num + 1:
                    print("received ack")
                    dup = 0
                    rtt = math.ceil((1 - 0.125) + 0.125 * (timeout - timer))
                    timer = 2 * rtt
                    timeout = 2 * rtt
                    number_of_acked_packets = 0
                    if max_seq_num >= received_packet_model.ack_num:
                        number_of_acked_packets = received_packet_model.ack_num - min_seq_num
                    else:
                        number_of_acked_packets = max_seq_num - min_seq_num + 1 # if you are a celever one, this is equal to cwnd :)
                    min_seq_num = received_packet_model.ack_num
                    max_seq_num = max(max_seq_num, received_packet_model.ack_num - 1)
                    increasing_cwnd_value = min(number_of_acked_packets, max_window - cwnd)
                    if ssthresh != - 1 and cwnd + increasing_cwnd_value >= ssthresh:
                        increasing_cwnd_value = ssthresh - cwnd
                        cs = ConnectionState.congestion_avoidance
                        pre_min_seq_num = min_seq_num
                        pre_max_seq_num = max_seq_num + number_of_acked_packets + increasing_cwnd_value
                    cwnd += increasing_cwnd_value
                    print(number_of_acked_packets, increasing_cwnd_value)
                    for i in range(number_of_acked_packets + increasing_cwnd_value):
                        max_seq_num += 1
                        print("sending " + str(max_seq_num))
                        if data.get(max_seq_num) is None:
                            break
                        sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                           seq_num=max_seq_num, ack_num=0, CWR=0, ACK=0, SYN=0, FIN=0,
                                                           window_size=cwnd, data=data[max_seq_num])
                        size, packet = sending_packet_model.to_bytes()
                        f_write.write(size)
                        f_write.write(packet)
                        f_write.flush()
                    if cs == ConnectionState.congestion_avoidance:
                        lock.release()
                        continue
                elif received_packet_model.ack_num == min_seq_num:
                    print("received dup ack")
                    dup += 1
                    if dup == 3:
                        timeout = 2 * rtt
                        timer = 2 * rtt
                        cs = ConnectionState.fast_recovery
                        cwnd //= 2
                        ssthresh = cwnd
                        max_seq_num = min_seq_num - 1
                        cwr = 1
                        for i in range(cwnd):
                            max_seq_num += 1
                            sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                               seq_num=max_seq_num, ack_num=0, CWR=cwr, ACK=0, SYN=0,
                                                               FIN=0,
                                                               window_size=cwnd, data=data[max_seq_num])
                            size, packet = sending_packet_model.to_bytes()
                            f_write.write(size)
                            f_write.write(packet)
                            f_write.flush()
                            if i == 0:
                                cwr = 0
            elif cs == ConnectionState.fast_recovery:
                print("enter in ConnectionState.fast_recovery")
                if received_packet_model.ack_num >= min_seq_num+1:
                    dup = 0
                    cs = ConnectionState.congestion_avoidance
                    pre_min_seq_num = min_seq_num
                    pre_max_seq_num = max_seq_num

            if cs == ConnectionState.congestion_avoidance:
                print("enter in ConnectionState.congestion_avoidance")
                if received_packet_model.ack_num >= min_seq_num + 1:
                    print("ack received")
                    dup = 0
                    rtt = math.ceil((1 - 0.125) + 0.125 * (timeout - timer))
                    timer = 2 * rtt
                    timeout = 2 * rtt
                    number_of_acked_packets = min(max_seq_num, received_packet_model.ack_num) - min_seq_num
                    min_seq_num = received_packet_model.ack_num
                    max_seq_num = max(max_seq_num, received_packet_model.ack_num - 1)
                    if pre_max_seq_num + 1 <= min_seq_num:
                        pre_min_seq_num = min_seq_num
                        pre_max_seq_num = min_seq_num + cwnd - 1
                        if cwnd < max_window:
                            cwnd += 1
                            number_of_acked_packets += 1
                            pre_max_seq_num += 1
                    for i in range(number_of_acked_packets):
                        max_seq_num += 1
                        print("sending " + max_seq_num)
                        if data.get(max_seq_num) is None:
                            break
                        sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                           seq_num=max_seq_num, ack_num=0, CWR=0, ACK=0, SYN=0, FIN=0,
                                                           window_size=cwnd, data=data[max_seq_num])
                        size, packet = sending_packet_model.to_bytes()
                        f_write.write(size)
                        f_write.write(packet)
                        f_write.flush()
                elif received_packet_model.ack_num == min_seq_num:
                    print("dup ack")
                    dup += 1
                    if dup == 3:
                        timeout = 2 * rtt
                        timer = 2 * rtt
                        cs = ConnectionState.fast_recovery
                        cwnd //= 2
                        ssthresh = cwnd
                        max_seq_num = min_seq_num - 1
                        cwr = 1
                        for i in range(cwnd):
                            max_seq_num += 1
                            sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                               seq_num=max_seq_num, ack_num=0, CWR=cwr, ACK=0, SYN=0,
                                                               FIN=0,
                                                               window_size=cwnd, data=data[max_seq_num])
                            size, packet = sending_packet_model.to_bytes()
                            f_write.write(size)
                            f_write.write(packet)
                            f_write.flush()
                            if i == 0:
                                cwr = 0
            lock.release()

        cs = ConnectionState.is_finished
        lock.release()

        # closing & removing files
        f_read.close()
        f_write.close()
        f_time.close()
        os.remove(read_file_path)
        os.remove(time_file_path)

        print("all file successfully removed and closed.")


class TimeThread(Thread):
    def __init__(self):
        super().__init__()

    def run(self):
        global timer, timeout, cwnd, data_array, data, first_data_packet_seq_num, \
            min_seq_num, max_seq_num, ssthresh, rtt, cs, f_write, f_read, f_time, dup, lock

        while True:
            f_time.readline()
            print(timeout, timer)
            lock.acquire()
            if cs == ConnectionState.is_finished:
                return
            timer -= 1
            if timer == 0:
                print("time out occurred!")
                ssthresh /= 2
                cwnd = 1
                max_seq_num = min_seq_num
                dup = 0
                cs = ConnectionState.slow_start
                timer = 2 *rtt
                timeout = 2 * rtt
                sending_packet_model = PacketModel(sender_port=sender_port, receiver_port=receiver_port,
                                                   seq_num=min_seq_num,
                                                   ack_num=0, CWR=1, ACK=0, SYN=0, FIN=0,
                                                   window_size=1, data=data[min_seq_num])
                size, packet = sending_packet_model.to_bytes()
                f_write.write(size)
                f_write.write(packet)
                f_write.flush()
            lock.release()


sender_port = sys.argv[1]
receiver_port = sys.argv[2]
init_rtt = sys.argv[3]
max_window = sys.argv[4]
file_path = sys.argv[5]
# sender_port = 34534
# receiver_port = 5678
# init_rtt = 3
# max_window = 10
# file_path = "./file.jpg"

read_file_path = "../pipes/" + "sender_" + str(sender_port) + "_data.pipe"
time_file_path = "../pipes/" + "sender_" + str(sender_port) + "_time.pipe"
transmitter_file_path = "../pipes/" + "forwardnet_data.pipe"

# creaing & opening files
os.mkfifo(read_file_path)
os.mkfifo(time_file_path)

f_time = open(time_file_path, 'rb')
print("passed")
f_write = open(transmitter_file_path, 'wb')
print("passed")
f_read = open(read_file_path, 'rb')
print("passed")
f_file = open(file_path, 'rb')

print("AA")

data_array = f_file.read()
f_file.close()

cwnd = 0
rtt = init_rtt
timer = 0
timeout = 0
cs = ConnectionState.sending_SYN
min_seq_num = randint(0, 2 ** 31)
max_seq_num = min_seq_num
first_data_packet_seq_num = min_seq_num + 2
ssthresh = -1
dup = 0

print(data_array)

tmp = min_seq_num + 2
data = {}
for i in range(0, len(data_array), 1480):
    if i + 1480 <= len(data_array):
        data[tmp] = data_array[i:i + 1480]
        tmp += 1
    else:
        data[tmp] = data_array[i:]

# print(data)
lock = Lock()

print(len(data))

ReaderThread().start()
TimeThread().start()


