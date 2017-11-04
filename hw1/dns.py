from socket import *
from lib import *
from threading import *
from struct import *
from random import *
import sys

class handler_thread(Thread):
    def __init__(self, data, client_address):
        super().__init__()
        self.data = data
        self.client_address = client_address

    def run(self):
        #print(data, client_address)

        # creating new socket
        self.new_socket = socket(AF_INET, SOCK_DGRAM)
        self.new_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

        # checking QR & QOPCODE
        if (data[2] >> 3) != 0:
            self.send_refused()
            return

        # creating log file
        message_id = self.extract_short(self.data, 0)[0]
        file = open(str(message_id) + ".txt", "w")

        # check whether it's site query or ip query
        labels = self.extract_name(self.data, 12)[0]
        is_site_query = False
        if len(labels) == 4:
            for label in labels:
                try:
                    int(label)
                except:
                    is_site_query = True
                    break
        else:
            is_site_query = True

        if is_site_query:
            self.handle_site_query(file)
        else:
            self.handle_ip_query(file)

        file.close()

    def handle_ip_query(self, file):
        #print("in ip query")
        # extracting request str
        labels = self.extract_name(self.data, 12)[0]
        labels.reverse()
        #print(labels)
        labels += ["in-addr", "arpa"]
        self.request_str = self.concat_labels(labels)
        self.is_request_str_found = False
        self.final_site = ""
        #print(self.request_str)

        # set root dns
        dns_ip = root_server_ip

        while not self.is_request_str_found:
            min_ip = "255.255.255.255"
            file.write("connecting to " + dns_ip + "\n")
            file.write("===============\n")
            # create packet
            packet = self.create_packet(self.request_str)
            # send pack to dns
            self.new_socket.sendto(packet, (dns_ip, 53))
            # listen for response
            res = self.new_socket.recvfrom(65507)[0]

            message_id = self.extract_short(res, 0)[0]
            byte3 = self.extract_mini_short(res, 2)[0]
            QR = (byte3 >> 7) & 1
            OPCODE = (byte3 >> 3) & 15
            AA = (byte3 >> 2) & 1
            TC = (byte3 >> 1) & 1
            RD = byte3 & 1
            byte4 = self.extract_mini_short(res, 3)[0]
            RA = (byte4 >> 7) & 1
            RCODE = byte4 & 15
            RCODE_STR = RCODE_STRING[RCODE]
            qdcount = self.extract_short(res, 4)[0]
            ancount = self.extract_short(res, 6)[0]
            nscount = self.extract_short(res, 8)[0]
            arcount = self.extract_short(res, 10)[0]
            # #print(qdcount)
            # #print(ancount)
            # #print(nscount)
            # #print(arcount)
            #print(res)
            file.write("HEADER\n")
            file.write("===============\n")
            header_str = ""
            header_str += "{\n"
            header_str += "additional count : " + str(arcount) + "\n"
            header_str += "answer count : " + str(ancount) + "\n"
            header_str += "authority count : " + str(nscount) + "\n"
            header_str += "id : " + str(message_id) + "\n"
            header_str += "is authoritative : " + ("True" if AA == 1 else "False") + "\n"
            header_str += "is response : " + ("True" if QR == 1 else "False") + "\n"
            header_str += "is truncated : " + ("True" if TC == 1 else "False") + "\n"
            header_str += "opcode : " + str(OPCODE) + "\n"
            header_str += "question count : " + str(qdcount) + "\n"
            header_str += "recursion available : " + ("True" if RA == 1 else "False") + "\n"
            header_str += "recursion desired : " + ("True" if RD == 1 else "False") + "\n"
            header_str += "reserved : 0" + "\n"
            header_str += "response code : " + RCODE_STR + "\n"
            header_str += "}\n"
            header_str += "===============\n"
            file.write(header_str)
            file.write("QUESTION\n")
            file.write("===============\n")
            index = 12
            labels = []
            for i in range(qdcount):
                labels, index = self.extract_name(res, index)
            QTYPE = self.extract_short(res, index)[0]
            index += 2
            QCLASS = self.extract_short(res, index)[0]
            index += 2
            question_str = "{\n"
            question_str += "Domain Name : " + self.concat_labels(labels) + "\n"
            question_str += "Query Class : " + str(QCLASS) + "\n"
            question_str += "Query Type : " + str(QTYPE) + "\n"
            question_str += "}\n"
            question_str += "===============\n"
            file.write(question_str)
            file.write("ANSWER\n")
            file.write("===============\n")
            answer_str = ""
            answer_str, index, answer_min_ip, answer_min_ns = self.ip_sections(res, index, ancount, answer_str)
            answer_str += "===============\n"
            file.write(answer_str)
            file.write("AUTHORITY\n")
            file.write("===============\n")
            authority_str = ""
            authority_str, index, authority_min_ip, authority_min_ns = self.ip_sections(res, index, nscount,
                                                                                        authority_str)
            authority_str += "===============\n"
            file.write(authority_str)
            file.write("ADDITIONAL\n")
            file.write("===============\n")
            additional_str = ""
            additional_str, index, additional_min_ip, additional_min_ns = self.ip_sections(res, index, arcount,
                                                                                           additional_str)
            additional_str += "===============\n"
            file.write(additional_str)
            #print("Dooooonz")
            if self.is_request_str_found:
                #print("success")
                self.send_site_answer_to_client()
                break
            else:
                # TODO
                #print(answer_min_ip, authority_min_ip, additional_min_ip)
                min_ip = self.return_minimum_ip(answer_min_ip, authority_min_ip)
                min_ip = self.return_minimum_ip(min_ip, additional_min_ip)
                #print(min_ip)
                if min_ip == "255.255.255.255":
                    if answer_min_ns is None:
                        if authority_min_ns is None:
                            if additional_min_ns is None:
                                self.send_refused()
                                break
                    tmp = ""
                    if answer_min_ns is not None:
                        tmp = answer_min_ns
                    elif authority_min_ns is not None:
                        tmp = authority_min_ns
                    elif additional_min_ns is not None:
                        tmp = additional_min_ns

                    if answer_min_ns is None:
                        answer_min_ns = tmp
                    if authority_min_ns is None:
                        authority_min_ns = tmp
                    if additional_min_ns is None:
                        additional_min_ns = tmp

                    min_ns = answer_min_ns
                    min_ns = min_ns if min_ns < authority_min_ns else authority_min_ns
                    min_ns = min_ns if min_ns < additional_min_ns else additional_min_ns
                    #print("DSFSDSSDFSF " + min_ns)
                    dns_ip = min_ns
                else:
                    # dns_ip = self.concat_labels(min_ip.split(".").reverse())
                    dns_ip = min_ip
                    # file.flush()

    def handle_site_query(self, file):
        # extracting request str
        labels = self.extract_name(self.data, 12)[0]
        if labels[0].find("www") != -1:
            del labels[0]
        else:
            if labels[0].find("https://") != -1:
                labels[0] = labels[0].replace("https://", "")
            elif labels[0].find("http://") != -1:
                labels[0] = labels[0].replace("http://", "")
        self.request_str = self.concat_labels(labels)
        self.is_request_str_found = False
        self.final_ip = ""
        #print(self.request_str)

        # set root dns
        dns_ip = root_server_ip

        while not self.is_request_str_found:
            min_ip = "255.255.255.255"
            file.write("connecting to " + dns_ip + "\n")
            file.write("===============\n")
            # create packet
            packet = self.create_packet(self.request_str)
            # send pack to dns
            self.new_socket.sendto(packet, (dns_ip, 53))
            # listen for response
            res = self.new_socket.recvfrom(65507)[0]

            message_id = self.extract_short(res, 0)[0]
            byte3 = self.extract_mini_short(res, 2)[0]
            QR = (byte3 >> 7) & 1
            OPCODE = (byte3 >> 3) & 15
            AA = (byte3 >> 2) & 1
            TC = (byte3 >> 1) & 1
            RD = byte3 & 1
            byte4 = self.extract_mini_short(res, 3)[0]
            RA = (byte4 >> 7) & 1
            RCODE = byte4 & 15
            RCODE_STR = RCODE_STRING[RCODE]
            qdcount = self.extract_short(res, 4)[0]
            ancount = self.extract_short(res, 6)[0]
            nscount = self.extract_short(res, 8)[0]
            arcount = self.extract_short(res, 10)[0]
            # #print(qdcount)
            # #print(ancount)
            # #print(nscount)
            # #print(arcount)
            #print(res)
            file.write("HEADER\n")
            file.write("===============\n")
            header_str = ""
            header_str += "{\n"
            header_str += "additional count : " + str(arcount) + "\n"
            header_str += "answer count : " + str(ancount) + "\n"
            header_str += "authority count : " + str(nscount) + "\n"
            header_str += "id : " + str(message_id) + "\n"
            header_str += "is authoritative : " + ("True" if AA == 1 else "False") + "\n"
            header_str += "is response : " + ("True" if QR == 1 else "False") + "\n"
            header_str += "is truncated : " + ("True" if TC == 1 else "False") + "\n"
            header_str += "opcode : " + str(OPCODE) + "\n"
            header_str += "question count : " + str(qdcount) + "\n"
            header_str += "recursion available : " + ("True" if RA == 1 else "False") + "\n"
            header_str += "recursion desired : " + ("True" if RD == 1 else "False") + "\n"
            header_str += "reserved : 0" + "\n"
            header_str += "response code : " + RCODE_STR + "\n"
            header_str += "}\n"
            header_str += "===============\n"
            file.write(header_str)
            file.write("QUESTION\n")
            file.write("===============\n")
            index = 12
            labels = []
            for i in range(qdcount):
                labels, index = self.extract_name(res, index)
            QTYPE = self.extract_short(res, index)[0]
            index += 2
            QCLASS = self.extract_short(res, index)[0]
            index += 2
            question_str = "{\n"
            question_str += "Domain Name : " + self.concat_labels(labels) + "\n"
            question_str += "Query Class : " + str(QCLASS) + "\n"
            question_str += "Query Type : " + str(QTYPE) + "\n"
            question_str += "}\n"
            question_str += "===============\n"
            file.write(question_str)
            file.write("ANSWER\n")
            file.write("===============\n")
            answer_str = ""
            answer_str, index, answer_min_ip = self.site_sections(res, index, ancount, answer_str)
            answer_str += "===============\n"
            file.write(answer_str)
            file.write("AUTHORITY\n")
            file.write("===============\n")
            authority_str = ""
            authority_str, index, authority_min_ip = self.site_sections(res, index, nscount, authority_str)
            authority_str += "===============\n"
            file.write(authority_str)
            file.write("ADDITIONAL\n")
            file.write("===============\n")
            additional_str = ""
            additional_str, index, additional_min_ip = self.site_sections(res, index, arcount, additional_str)
            additional_str += "===============\n"
            file.write(additional_str)
            #print("Dooooonz")
            if self.is_request_str_found:
                #print("success")
                self.send_ip_answer_to_client()
                break
            else:
                # TODO
                #print(answer_min_ip, authority_min_ip, additional_min_ip)
                min_ip = self.return_minimum_ip(answer_min_ip, authority_min_ip)
                min_ip = self.return_minimum_ip(min_ip, additional_min_ip)
                #print(min_ip)
                if min_ip == "255.255.255.255":
                    #print("WAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaay")
                    self.send_refused()
                    break
                else:
                    dns_ip = min_ip
                    # file.flush()

    def create_packet(self, address):
        buffer = bytearray(1000)
        pack_into('!H', buffer, 0, randint(0, 65000))  # message ID
        # pack_into('!B', buffer, 2, 16)  # QDCount
        pack_into('!H', buffer, 4, 1)  # QDCount
        index = 12
        labels = address.split(".")
        for i in range(len(labels)):
            n = len(labels[i])
            n &= ~(1 << 7)
            n &= ~(1 << 6)
            pack_into('!B', buffer, index, n)
            index += 1
            pack_into("!" + str(n) + "s", buffer, index, str.encode(labels[i]))
            index += n
        pack_into('!B', buffer, index, 0)
        index += 2
        pack_into('!B', buffer, index, 255)
        index += 2
        pack_into('!B', buffer, index, 1)
        # index += 1
        i = len(buffer)-1
        while i != index:
            del buffer[i]
            i -= 1
        #print(buffer)
        return buffer

    def ip_sections(self, res, index, number, section_str):
        min_ip = "255.255.255.255"
        min_ns = None
        for i in range(number):
            #print("i: " + str(i))
            labels, index = self.extract_name(res, index)
            TYPE, index = self.extract_short(res, index)
            CLASS, index = self.extract_short(res, index)
            TTL, index = self.extract_int(res, index)
            RDLENGTH, index = self.extract_short(res, index)
            #print(labels)
            #print(TYPE)
            #print(CLASS)
            #print(TTL)
            #print(RDLENGTH)
            section_str += "{\n"
            section_str += "class : " + str(CLASS) + "\n"
            section_str += "name : " + self.concat_labels(labels) + "\n"
            # extracting RDATA
            if TYPE == 1:  # A TYPE TODO
                IPV4_ADDRESS = ""
                for j in range(4):
                    tmp, index = self.extract_mini_short(res, index)
                    IPV4_ADDRESS += str(tmp)
                    if j + 1 != 4:
                        IPV4_ADDRESS += "."
                section_str += "rdata : " + IPV4_ADDRESS + "\n"
                #print(IPV4_ADDRESS)
                if self.compare_ip(min_ip, IPV4_ADDRESS):
                    #print(min_ip, IPV4_ADDRESS)
                    min_ip = IPV4_ADDRESS
            elif TYPE == 2:  # NS TYPE
                labels, index = self.extract_name(res, index)
                section_str += "rdata : " + self.concat_labels(labels) + "\n"
                #print(labels)
                if (min_ns is None) or min_ns > self.concat_labels(labels):
                    min_ns = self.concat_labels(labels)
            elif TYPE == 5:  # CNAME TYPE
                labels, index = self.extract_name(res, index)
                section_str += "rdata : " + self.concat_labels(labels) + "\n"
                #print(labels)
            elif TYPE == 6:  # SOA TYPE
                PNS_labels, index = self.extract_name(res, index)
                AMB_labels, index = self.extract_name(res, index)
                SN, index = self.extract_int(res, index)
                REFRESHi, index = self.extract_int(res, index)
                RETRYi, index = self.extract_int(res, index)
                EL, index = self.extract_int(res, index)
                MT, index = self.extract_int(res, index)
                section_str += "rdata :\n"
                section_str += "{\n"
                section_str += "Admin MB : " + self.concat_labels(AMB_labels) + "\n"
                section_str += "Expiration Limit : " + str(EL) + "\n"
                section_str += "Minimum TTL : " + str(MT) + "\n"
                section_str += "Primary NS : " + self.concat_labels(PNS_labels) + "\n"
                section_str += "Refresh interval : " + str(REFRESHi) + "\n"
                section_str += "Retry interval : " + str(RETRYi) + "\n"
                section_str += "Serial Number : " + str(SN) + "\n"
                section_str += "}\n"
                #print("SOA...")
            elif TYPE == 12:  # PTR TYPE
                ptr_labels, index = self.extract_name(res, index)
                section_str += "rdata : " + self.concat_labels(ptr_labels) + "\n"
                #print(ptr_labels)
                if self.is_equal_to_request_str(self.concat_labels(labels)):
                    if self.is_request_str_found:
                        if self.final_site > self.concat_labels(ptr_labels):
                            self.final_site = self.concat_labels(ptr_labels)
                    else:
                        self.is_request_str_found = True
                        self.final_site = self.concat_labels(ptr_labels)
            elif TYPE == 15:  # MX TYPE
                PREF, index = self.extract_short(res, index)
                labels, index = self.extract_name(res, index)
                section_str += "rdata :\n"
                section_str += "{\n"
                section_str += "Mail Exchanger : " + self.concat_labels(labels) + "\n"
                section_str += "Preference : " + str(PREF) + "\n"
                section_str += "}\n"
                #print(PREF)
                #print(labels)
            elif TYPE == 28:  # AAAA TYPE
                IPV6_ADDRESS = ""
                for j in range(8):
                    tmp, index = self.extract_short(res, index)
                    tmp = hex(tmp)
                    tmp = tmp.replace("0x", "")
                    while len(tmp) < 4:
                        tmp = "0" + tmp
                    IPV6_ADDRESS += tmp
                    if j + 1 != 8:
                        IPV6_ADDRESS += ":"
                # IPV6_ADDRESS = ipaddress.ip_address(IPV6_ADDRESS).exploded
                section_str += "rdata : " + IPV6_ADDRESS + "\n"
                #print(IPV6_ADDRESS)
            elif TYPE == 16:  # TXT TYPE
                txt = unpack_from("!" + str(RDLENGTH) + "s", res, index)[0]
                index += RDLENGTH
                section_str += "rdata : " + txt.decode() + "\n"
                #print(txt)
            else:
                section_str += "rdata :\n"
                index += RDLENGTH
            section_str += "rdlength : " + str(RDLENGTH) + "\n"
            section_str += "ttl : " + str(TTL) + "\n"
            section_str += "type : " + (
                ANSWER_TYPE.get(TYPE) if ANSWER_TYPE.get(TYPE) is not None else str(TYPE)) + "\n"
            section_str += "}\n"
            #print("=============")
        return section_str, index, min_ip, min_ns

    def site_sections(self, res, index, number, section_str):
        min_ip = "255.255.255.255"
        for i in range(number):
            #print("i: " + str(i))
            labels, index = self.extract_name(res, index)
            TYPE, index = self.extract_short(res, index)
            CLASS, index = self.extract_short(res, index)
            TTL, index = self.extract_int(res, index)
            RDLENGTH, index = self.extract_short(res, index)
            #print(labels)
            #print(TYPE)
            #print(CLASS)
            #print(TTL)
            #print(RDLENGTH)
            section_str += "{\n"
            section_str += "class : " + str(CLASS) + "\n"
            section_str += "name : " + self.concat_labels(labels) + "\n"
            # extracting RDATA
            if TYPE == 1:  # A TYPE TODO
                IPV4_ADDRESS = ""
                for j in range(4):
                    tmp, index = self.extract_mini_short(res, index)
                    IPV4_ADDRESS += str(tmp)
                    if j + 1 != 4:
                        IPV4_ADDRESS += "."
                section_str += "rdata : " + IPV4_ADDRESS + "\n"
                #print(IPV4_ADDRESS)
                if self.is_equal_to_request_str(self.concat_labels(labels)):
                    if self.is_request_str_found:
                        if self.compare_ip(self.final_ip, IPV4_ADDRESS):
                            self.final_ip = IPV4_ADDRESS
                    else:
                        self.is_request_str_found = True
                        self.final_ip = IPV4_ADDRESS
                elif (not self.is_request_str_found) and self.compare_ip(min_ip, IPV4_ADDRESS):
                    #print(min_ip, IPV4_ADDRESS)
                    min_ip = IPV4_ADDRESS
            elif TYPE == 2:  # NS TYPE
                labels, index = self.extract_name(res, index)
                section_str += "rdata : " + self.concat_labels(labels) + "\n"
                #print(labels)
            elif TYPE == 5:  # CNAME TYPE
                labels, index = self.extract_name(res, index)
                section_str += "rdata : " + self.concat_labels(labels) + "\n"
                #print(labels)
            elif TYPE == 6:  # SOA TYPE
                PNS_labels, index = self.extract_name(res, index)
                AMB_labels, index = self.extract_name(res, index)
                SN, index = self.extract_int(res, index)
                REFRESHi, index = self.extract_int(res, index)
                RETRYi, index = self.extract_int(res, index)
                EL, index = self.extract_int(res, index)
                MT, index = self.extract_int(res, index)
                section_str += "rdata :\n"
                section_str += "{\n"
                section_str += "Admin MB : " + self.concat_labels(AMB_labels) + "\n"
                section_str += "Expiration Limit : " + str(EL) + "\n"
                section_str += "Minimum TTL : " + str(MT) + "\n"
                section_str += "Primary NS : " + self.concat_labels(PNS_labels) + "\n"
                section_str += "Refresh interval : " + str(REFRESHi) + "\n"
                section_str += "Retry interval : " + str(RETRYi) + "\n"
                section_str += "Serial Number : " + str(SN) + "\n"
                section_str += "}\n"
                #print("SOA...")
            elif TYPE == 12:  # PTR TYPE
                labels, index = self.extract_name(res, index)
                section_str += "rdata : " + self.concat_labels(labels) + "\n"
                #print(labels)
            elif TYPE == 15:  # MX TYPE
                PREF, index = self.extract_short(res, index)
                labels, index = self.extract_name(res, index)
                section_str += "rdata :\n"
                section_str += "{\n"
                section_str += "Mail Exchanger : " + self.concat_labels(labels) + "\n"
                section_str += "Preference : " + str(PREF) + "\n"
                section_str += "}\n"
                #print(PREF)
                #print(labels)
            elif TYPE == 28:  # AAAA TYPE
                IPV6_ADDRESS = ""
                for j in range(8):
                    tmp, index = self.extract_short(res, index)
                    tmp = hex(tmp)
                    tmp = tmp.replace("0x", "")
                    while len(tmp) < 4:
                        tmp = "0" + tmp
                    IPV6_ADDRESS += tmp
                    if j + 1 != 8:
                        IPV6_ADDRESS += ":"
                # IPV6_ADDRESS = ipaddress.ip_address(IPV6_ADDRESS).exploded
                section_str += "rdata : " + IPV6_ADDRESS + "\n"
                #print(IPV6_ADDRESS)
            elif TYPE == 16:  # TXT TYPE
                txt = unpack_from("!" + str(RDLENGTH) + "s", res, index)[0]
                index += RDLENGTH
                section_str += "rdata : " + txt.decode() + "\n"
                #print(txt)
            else:
                section_str += "rdata :\n"
                index += RDLENGTH
            section_str += "rdlength : " + str(RDLENGTH) + "\n"
            section_str += "ttl : " + str(TTL) + "\n"
            section_str += "type : " + (
                ANSWER_TYPE.get(TYPE) if ANSWER_TYPE.get(TYPE) is not None else str(TYPE)) + "\n"
            section_str += "}\n"
            #print("=============")
        return section_str, index, min_ip

    def send_site_answer_to_client(self):
        buffer = bytearray(1000)
        pack_into('!H', buffer, 0, self.extract_short(self.data, 0)[0])  # message ID
        pack_into('!B', buffer, 2, 128)  # byte3
        pack_into('!H', buffer, 6, 1)  # ANCount
        index = 12
        labels = self.request_str.split(".")
        # labels.reverse()
        # del labels[0]
        # del labels[0] # TODO ?!?!?!?!?!?!?!!?!?!?!?!!?!?!?!?!?!?!?!?!?!!??!?!?!?!??
        for i in range(len(labels)):
            n = len(labels[i])
            n &= ~(1 << 7)
            n &= ~(1 << 6)
            pack_into('!B', buffer, index, n)
            index += 1
            pack_into("!" + str(n) + "s", buffer, index, str.encode(labels[i]))
            index += n
        pack_into('!B', buffer, index, 0)
        index += 1
        pack_into('!H', buffer, index, 12)  # TYPE
        index += 2
        pack_into('!H', buffer, index, 1)  # CLASS
        index += 2
        pack_into('!i', buffer, index, 3600)  # TTL
        index += 4
        rdlength_index = index
        pack_into('!H', buffer, index, 0)  # RDLENGTH
        index += 2
        labels = self.final_site.split(".")
        rdlength = 0
        for i in range(len(labels)):
            n = len(labels[i])
            n &= ~(1 << 7)
            n &= ~(1 << 6)
            pack_into('!B', buffer, index, n)
            index += 1
            rdlength += 1
            pack_into("!" + str(n) + "s", buffer, index, str.encode(labels[i]))
            index += n
            rdlength += n
        pack_into('!B', buffer, index, 0)
        # index += 1
        rdlength += 1
        pack_into('!H', buffer, rdlength_index, rdlength)  # RDLENGTH

        i = len(buffer)-1
        while i != index:
            del buffer[i]
            i -= 1

        self.new_socket.sendto(buffer, self.client_address)
        return

    def send_ip_answer_to_client(self):
        buffer = bytearray(1000)
        pack_into('!H', buffer, 0, self.extract_short(self.data, 0)[0])  # message ID
        pack_into('!B', buffer, 2, 128)  # byte3
        pack_into('!H', buffer, 6, 1)  # ANCount
        index = 12
        labels = self.request_str.split(".")
        for i in range(len(labels)):
            n = len(labels[i])
            n &= ~(1 << 7)
            n &= ~(1 << 6)
            pack_into('!B', buffer, index, n)
            index += 1
            pack_into("!" + str(n) + "s", buffer, index, str.encode(labels[i]))
            index += n
        pack_into('!B', buffer, index, 0)
        index += 1
        pack_into('!H', buffer, index, 1)  # TYPE
        index += 2
        pack_into('!H', buffer, index, 1)  # CLASS
        index += 2
        pack_into('!i', buffer, index, 3600)  # TTL
        index += 4
        pack_into('!H', buffer, index, 4)  # RDLENGTH
        index += 2
        ip = self.final_ip.split(".")
        pack_into('!B', buffer, index, int(ip[0]))  # RDATA
        index += 1
        pack_into('!B', buffer, index, int(ip[1]))  # RDATA
        index += 1
        pack_into('!B', buffer, index, int(ip[2]))  # RDATA
        index += 1
        pack_into('!B', buffer, index, int(ip[3]))  # RDATA

        i = len(buffer)-1
        while i != index:
            del buffer[i]
            i -= 1

        self.new_socket.sendto(buffer, self.client_address)
        return

    def compare_ip(self, ip1, ip2):
        ip1 = list(map(int, ip1.split(".")))
        ip2 = list(map(int, ip2.split(".")))
        if ip1[0] > ip2[0]: return True
        if ip1[0] < ip2[0]: return False
        if ip1[1] > ip2[1]: return True
        if ip1[1] < ip2[1]: return False
        if ip1[2] > ip2[2]: return True
        if ip1[2] < ip2[2]: return False
        if ip1[3] > ip2[3]: return True
        if ip1[3] < ip2[3]: return False
        return False

    def return_minimum_ip(self, ip1, ip2):
        if self.compare_ip(ip1, ip2):
            return ip2
        return ip1

    def is_equal_to_request_str(self, other):
        # TODO
        other = other.split(".")
        request_str = self.request_str.split(".")
        i = 0
        j = 0
        while i < len(other) and j < len(request_str):
            if other[i] != request_str[j]:
                return False
            i += 1
            j += 1
        return True

    def concat_labels(self, labels):
        result = ""
        for b in range(len(labels)):
            result += labels[b]
            if b + 1 != len(labels):
                result += "."
            else:
                break
        return result

    def send_refused(self):
        buffer = bytearray(12)
        pack_into('!H', buffer, 0, self.extract_short(self.data, 0)[0])  # message ID
        pack_into('!B', buffer, 2, 128)  # byte3
        pack_into('!B', buffer, 3, 5)  # byte4
        self.new_socket.sendto(buffer, self.client_address)
        return

    def is_pointer_format(self, res, index):
        m = self.extract_mini_short(res, index)[0]
        return (m >> 6) == 3

    def extract_name(self, res, index):
        labels = []
        while True:
            if self.is_pointer_format(res, index):
                m, index = self.extract_short(res, index)
                m &= ~(1 << 15)
                m &= ~(1 << 14)
                pointer_labels = self.extract_name(res, m)[0]
                labels += pointer_labels
                return labels, index
            m, index = self.extract_mini_short(res, index)
            # #print("m: " + str(m))
            if m == 0:
                break
            label = unpack_from("!" + str(m) + "s", res, index)[0]
            labels += [label.decode()]
            index += m
        return labels, index

    def extract_int(self, res, index):
        number = unpack_from("!i", res, index)[0]
        # number = int.from_bytes(tmp, byteorder="big")
        index += 4
        return number, index

    def extract_short(self, res, index):
        number = unpack_from("!H", res, index)[0]
        # number = int.from_bytes(tmp, byteorder="big")
        index += 2
        return number, index

    def extract_mini_short(self, res, index):
        tmp = unpack_from("!c", res, index)[0]
        number = int.from_bytes(tmp, byteorder="big")
        index += 1
        return number, index


# root_server_ip = input()  # TODO

root_server_ip = sys.argv[1]

listen_socket = socket(AF_INET, SOCK_DGRAM)
listen_socket.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
listen_socket.bind(('', 15353))

while True:
    data, client_address = listen_socket.recvfrom(1024)
    handler_thread(data, client_address).start()
