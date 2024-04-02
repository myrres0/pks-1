import ruamel.yaml
from ruamel.yaml.scalarstring import LiteralScalarString
from scapy.all import rdpcap

Ethernet_II = "Ethernet II"
IEEE_RAW = "IEEE 802.3 Raw"
IEEE_LCC_SNAP = "IEEE 802.3 LLC & SNAP"
IEEE_LCC = "IEEE 802.3 LLC"


def read_pcap_to_list(file):
    packets = rdpcap(file)
    list_packets = []
    for packet in packets:
        list_packets.append(bytes(packet).hex())
    return list_packets


def find_src_mac(hex_string):
    src_mac = hex_string[12:24]
    return ":".join([src_mac[i:i + 2] for i in range(0, len(src_mac), 2)])


def find_dst_mac(hex_string):
    dst_mac = hex_string[:12]
    return ":".join([dst_mac[i:i + 2] for i in range(0, len(dst_mac), 2)])


def find_len_frame_pcap(hex_string):
    return int(len(hex_string) / 2)


def find_len_frame_medium(hex_string):
    if len(hex_string) / 2 < 60:
        return 64
    return int(len(hex_string) / 2 + 4)


def find_frame_type(hex_string):
    if int(hex_string[24:28], 16) > 1536:
        return Ethernet_II
    return get_ieee_type(hex_string)


def get_ieee_type(hex_string):
    if hex_string[28:32] == "ffff":
        return IEEE_RAW
    if hex_string[28:32] == "aaaa":
        return IEEE_LCC_SNAP
    return IEEE_LCC


def find_ieee_pid(hex_string):
    pid_str = hex_string[40:44]
    return "DTP" if pid_str == "2004" else "CDP" if pid_str == "2000" else "PVSTP+" if pid_str == "010b" else "AppleTalk"  # if pid_str == "809B" else "unknown"


def find_ieee_sap(hex_string):
    hex_sap = hex_string[28:30]
    return "STP" if hex_sap == "42" else "IPX" if hex_sap == "e0" else "NETBIOS"  # if hex_sap == "f0" else "unknown"


def hex_format(bytes_str):
    result = ''
    for i, byte in enumerate(bytes_str):
        result += f'{byte:02X}' + (' ' if (i + 1) % 16 != 0 else '\n')
    return result


def find_eth_protocol(hex_string):
    with open("./protocols/ETH.txt", "r") as file:
        for line in file:
            if hex_string[24:28] == line[:4]:
                return line[5:].strip()
    return "unknown"


def find_source_ip(hex_string):
    source_ip = ""
    if find_eth_protocol(hex_string) == "ARP":
        source_ip = hex_string[56:64]
    else:
        source_ip = hex_string[52:60]
    hex_list = [source_ip[i:i + 2] for i in range(0, len(source_ip), 2)]
    return ".".join([str(int(hex_part, 16)) for hex_part in hex_list])


def find_dst_ip(hex_string):
    dst_ip = ""
    if find_eth_protocol(hex_string) == "ARP":
        dst_ip = hex_string[76:84]
    else:
        dst_ip = hex_string[60:68]
    hex_list = [dst_ip[i:i + 2] for i in range(0, len(dst_ip), 2)]
    return ".".join([str(int(hex_part, 16)) for hex_part in hex_list])


def find_nested_protocol_ipv4(hex_string):
    protocol = str(int(hex_string[46:48], 16))
    with open("./protocols/IPv4.txt", "r") as file:
        for line in file:
            if protocol == line[:4].strip():
                return line[4:].strip()
    return "unknown"


def find_src_port(hex_string):
    if find_eth_protocol(hex_string) == "IPv6":
        return int(hex_string[108:112], 16)
    return int(hex_string[68:72], 16)


def find_dst_port(hex_string):
    if find_eth_protocol(hex_string) == "IPv6":
        return int(hex_string[112:116], 16)
    return int(hex_string[72:76], 16)


def find_app_protocol(hex_string):
    type_protocol = find_nested_protocol_ipv4(hex_string)
    src_port = find_src_port(hex_string)
    dst_port = find_dst_port(hex_string)
    if type_protocol == "TCP":
        with open("./protocols/TCP.txt", "r") as file:
            for line in file:
                if str(src_port) == line.split()[0] or str(dst_port) == line.split()[0]:
                    return line.split()[1].strip()
    with open("./protocols/UDP.txt", "r") as file:
        for line in file:
            if str(src_port) == line.split()[0] or str(dst_port) == line.split()[0]:
                return line.split()[1].strip()
    return ""


def count_ips(packets):
    ip_list = []
    for i in range(0, len(packets), 1):
        if find_frame_type(packets[i]) == Ethernet_II and find_eth_protocol(packets[i]) == "IPv4":
            ip_list.append(find_source_ip(packets[i]))
    ip_count_dict = {}
    for ip in ip_list:
        if ip in ip_count_dict:
            ip_count_dict[ip] += 1
        else:
            ip_count_dict[ip] = 1
    # Create a list of dictionaries with 'ip' and 'count' keys
    return [{'node': ip, 'number_of_sent_packets': count} for ip, count in ip_count_dict.items()]


def most_popular_ip(lst_of_ip):
    count_maxes = max(ip['number_of_sent_packets'] for ip in lst_of_ip)
    max_dict_list = [ip for ip in lst_of_ip if ip['number_of_sent_packets'] == count_maxes]
    ip_list = [item['node'] for item in max_dict_list]
    return ip_list


def find_flags(list_of_frames, search_name):
    filtered_list = []
    for dictionary in list_of_frames:
        if 'app_protocol' in dictionary and dictionary['app_protocol'] == search_name:
            filtered_list.append(dictionary)
    for el in filtered_list:
        tcp_flags_byte = int(el['hexa_frame'].replace(" ", "")[96:98], 16)
        el['syn_flag'] = (tcp_flags_byte & 2) >> 1
        el['ack_flag'] = (tcp_flags_byte & 16) >> 4
        el['fin_flag'] = tcp_flags_byte & 1
        el['rst_flag'] = (tcp_flags_byte & 4) >> 2
    return filtered_list


def group_communication(filtered_list):
    grouped_data = {}
    for packet in filtered_list:
        src_ip = packet['src_ip']
        dst_ip = packet['dst_ip']
        src_port = packet['src_port']
        dst_port = packet['dst_port']

        port_pair = tuple(sorted([src_port, dst_port]))
        ip_pair = tuple(sorted([src_ip, dst_ip]))
        key = tuple([ip_pair, port_pair])

        if key in grouped_data:
            grouped_data[key].append(packet)
        else:
            grouped_data[key] = [packet]

    grouped_list = [packet_list for packet_list in grouped_data.values()]
    return grouped_list


def check_open_communication(communication):
    if communication[0]['syn_flag'] == 1 and communication[0]['ack_flag'] == 0:
        if communication[1]['syn_flag'] == 1 and communication[1]['ack_flag'] == 1:
            if communication[2]['syn_flag'] == 0 and communication[2]['ack_flag'] == 1:
                return True
    elif communication[0]['syn_flag'] == 1 and communication[0]['ack_flag'] == 0:
        if communication[1]['syn_flag'] == 1 and communication[1]['ack_flag'] == 0:
            if communication[2]['syn_flag'] == 0 and communication[2]['ack_flag'] == 1:
                if communication[3]['syn_flag'] == 0 and communication[3]['ack_flag'] == 1:
                    return True
    return False


def check_close_communication(communication):
    last_index = len(communication) - 1
    if communication[last_index]['fin_flag'] == 0 and communication[last_index]['ack_flag'] == 1:
        if communication[last_index - 1]['fin_flag'] == 1 and communication[last_index - 1]['ack_flag'] == 1:
            if communication[last_index - 2]['fin_flag'] == 0 and communication[last_index - 2]['ack_flag'] == 1:
                if communication[last_index - 3]['fin_flag'] == 1 and communication[last_index - 3]['ack_flag'] == 1:
                    return True
            elif communication[last_index-2]['fin_flag'] == 1 and communication[last_index-2]['ack_flag'] == 1:
                return True
    for i in range(0, len(communication), 1):
        if communication[i]['rst_flag'] == 1:
            return True
    return False


def check_completed_communication(communication):
    if len(communication) < 6:
        return False
    if check_open_communication(communication) and check_close_communication(communication):
        return True
    return False


def first_uncompleted_communication(grouped_list):
    for i in range(0, len(grouped_list), 1):
        if not check_completed_communication(grouped_list[i]):
            result_dict = {
                'number_comm': i + 1,
                'packets': grouped_list[i]
            }
            return result_dict
    return None


# ! task 4 - analyze TCP
def print_completed_communications(list_of_frames, search_name):
    grouped_list = group_communication(find_flags(list_of_frames, search_name))
    list_of_communications = []
    first_uncomp_comm = None
    if first_uncompleted_communication(grouped_list):
        first_uncomp_comm = first_uncompleted_communication(grouped_list)

    file_path = "./output/tcp.yaml"
    with open(file_path, 'w') as yaml_file:
        for i in range(0, len(grouped_list), 1):
            if check_open_communication(grouped_list[i]) and check_close_communication(grouped_list[i]):
                for j in range(0, len(grouped_list[i]), 1):
                    grouped_list[i][j].pop('syn_flag')
                    grouped_list[i][j].pop('ack_flag')
                    grouped_list[i][j].pop('fin_flag')
                    grouped_list[i][j].pop('rst_flag')
                dictionary_to_yaml = {
                    'number_comm': i + 1,
                    'src_comm': grouped_list[i][0]['src_ip'],
                    'dst_comm': grouped_list[i][0]['dst_ip'],
                    'packets': grouped_list[i]
                }
                list_of_communications.append(dictionary_to_yaml)
        final_dict = {
            'name': 'PKS2023/24',
            'pcap_name': filename,
            'filter_name': search_name,
        }
        if list_of_communications:
            final_dict['complete_comms'] = list_of_communications
        if first_uncomp_comm:
            final_dict['partial_comms'] = first_uncomp_comm
        yaml = ruamel.yaml.YAML()
        yaml.dump(final_dict, yaml_file)


def udp_sort(list_of_frames):
    udp_list = []
    for i in range(0, len(list_of_frames), 1):
        if 'protocol' in list_of_frames[i] and list_of_frames[i]['protocol'] == "UDP":
            udp_list.append(list_of_frames[i])
    return udp_list


def find_tftp(udp_list):
    src_port = -1
    dst_port = -1
    ip1 = ""
    ip2 = ""
    list_of_pairs = []
    dictionary_tftp = {}
    for udp_dict in udp_list:
        if udp_dict['dst_port'] == 69:
            dst_port = udp_dict['src_port']
            ip1 = udp_dict['src_ip']
            ip2 = udp_dict['dst_ip']
        if udp_dict['dst_port'] == dst_port:
            src_port = udp_dict['src_port']
            list_of_pairs.append([src_port, dst_port, ip1, ip2])
            src_port = -1
            dst_port = -1

    for pair in list_of_pairs:
        for udp_dict in udp_list:
            if (((udp_dict['src_port'] == pair[0] and udp_dict['dst_port'] == pair[1]) or
                 (udp_dict['src_port'] == pair[1] and udp_dict['dst_port'] == pair[0])) and
                    ((udp_dict['src_ip'] == pair[2] and udp_dict['dst_ip'] == pair[3]) or
                     (udp_dict['src_ip'] == pair[3] and udp_dict['dst_ip'] == pair[2]))):
                key = tuple(sorted([pair[0], pair[1]]))
                if key in dictionary_tftp:
                    dictionary_tftp[key].append(udp_dict)
                else:
                    dictionary_tftp[key] = [udp_dict]
    grouped_list = [packet_list for packet_list in dictionary_tftp.values()]
    return grouped_list


def check_complete_tftp(communication):
    for i in range(0, len(communication), 1):
        length = int(communication[i]['hexa_frame'].replace(" ", "")[78:82], 16)
        opcode = communication[i]['hexa_frame'].replace(" ", "")[86:90]
        if opcode == "0005":
            return True
        if i < len(communication) - 1:
            if opcode == "0003" and length < 512:
                if communication[i + 1]['hexa_frame'].replace(" ", "")[86:90] == "0004":
                    return True

    return False


def tftp_to_yaml(list_of_frames):
    udp_list = udp_sort(list_of_frames)
    grouped_list = find_tftp(udp_list)
    file_path = "./output/tftp.yaml"
    list_of_complete = []
    list_of_uncomplete = []
    count_complete = 1
    count_uncomplete = 1
    with open(file_path, 'w') as yaml_file:
        for i in range(0, len(grouped_list), 1):
            if check_complete_tftp(grouped_list[i]):
                dictionary_to_yaml = {
                    'number_comm': count_complete,
                    'src_comm': grouped_list[i][0]['src_ip'],
                    'dst_comm': grouped_list[i][0]['dst_ip'],
                    'packets': grouped_list[i]
                }
                count_complete += 1
                list_of_complete.append(dictionary_to_yaml)

            else:
                dictionary_to_yaml = {
                    'number_comm': count_uncomplete,
                    'src_comm': grouped_list[i][0]['src_ip'],
                    'dst_comm': grouped_list[i][0]['dst_ip'],
                    'packets': grouped_list[i]
                }
                count_uncomplete += 1
                list_of_uncomplete.append(dictionary_to_yaml)

        final_dict = {
            'name': 'PKS2023/24',
            'pcap_name': filename,
            'filter_name': 'TFTP',
        }
        if list_of_complete:
            final_dict['complete_comms'] = list_of_complete
        if list_of_uncomplete:
            final_dict['partial_communication'] = list_of_uncomplete
        yaml = ruamel.yaml.YAML()
        yaml.dump(final_dict, yaml_file)


def icmp_sort(list_of_frames):
    icmp_list = []
    for i in range(0, len(list_of_frames), 1):
        if 'protocol' in list_of_frames[i] and list_of_frames[i]['protocol'] == "ICMP":
            icmp_list.append(list_of_frames[i])
    return icmp_list


def find_icmp_type(hex_string):
    num = int(hex_string, 16)
    with open("./protocols/ICMP.txt", "r") as file:
        for line in file:
            if str(num) == line[:3].strip():
                return line[3:].strip()


def group_icmp(icmp_list):
    for packet in icmp_list:
        packet['icmp_type'] = find_icmp_type(packet['hexa_frame'].replace(' ', '')[70:72])
        if packet['icmp_type'] == "Echo Request" or packet['icmp_type'] == "Echo Reply":
            id_pack = packet['hexa_frame'].replace(' ', '')[78:82]
            seq = packet['hexa_frame'].replace(' ', '')[82:86]
            packet['icmp_id'] = int(id_pack, 16)
            packet['icmp_seq'] = int(seq, 16)
        if packet['icmp_type'] == "Time Exceeded":
            id_pack = packet['hexa_frame'].replace(' ', '')[136:140]
            packet['icmp_id'] = int(id_pack, 16)
            seq = packet['hexa_frame'].replace(' ', '')[140:144]
            packet['icmp_seq'] = int(seq, 16)

    grouped_data = {}
    uncompleted_icmp = []
    for packet in icmp_list:
        src_ip = packet['src_ip']
        dst_ip = packet['dst_ip']
        if packet['icmp_type'] == "Echo Request" or packet['icmp_type'] == "Echo Reply":
            id_pack = packet['icmp_id']
            ip_pair = tuple(sorted([src_ip, dst_ip]))
            key = tuple([ip_pair, id_pack])

            if key in grouped_data:
                grouped_data[key].append(packet)
            else:
                grouped_data[key] = [packet]
        else:
            uncompleted_icmp.append(packet)

    new_grouped_data = {}

    for packet in grouped_data:
        if len(grouped_data[packet]) < 2:
            uncompleted_icmp.append(grouped_data[packet])
        else:
            new_grouped_data[packet] = grouped_data[packet]

    grouped_complete_list = [packet_list for packet_list in new_grouped_data.values()]

    list_dict_complete = []
    for i in range(0, len(grouped_complete_list), 1):
        dict_comp = {
            'number_comm': i + 1,
            'src_comm': grouped_complete_list[i][0]['src_ip'],
            'dst_comm': grouped_complete_list[i][0]['dst_ip'],
            'packets': grouped_complete_list[i]
        }
        list_dict_complete.append(dict_comp)
    list_dict_uncomplete = []
    for i in range(0, len(uncompleted_icmp), 1):
        dict_uncomp = {
            'number_comm': i + 1,
            'packets': uncompleted_icmp[i]
        }
        list_dict_uncomplete.append(dict_uncomp)
    return list_dict_complete, list_dict_uncomplete


def icmp_to_yaml(list_of_frames):
    icmp_list = icmp_sort(list_of_frames)
    grouped_list, uncompleted_icmp = group_icmp(icmp_list)
    file_path = "./output/icmp.yaml"
    with open(file_path, 'w')as file:

        final_dict = {
            'name': 'PKS2023/24',
            'pcap_name': filename,
            'filter_name': 'ICMP',
        }
        if grouped_list:
            final_dict['complete_comms'] = grouped_list
        if uncompleted_icmp:
            final_dict['partial_comms'] = uncompleted_icmp
        yaml = ruamel.yaml.YAML()
        yaml.dump(final_dict, file)


def arp_sort(list_of_frames):
    arp_list = []
    for i in range(0, len(list_of_frames), 1):
        if 'ether_type' in list_of_frames[i] and list_of_frames[i]['ether_type'] == "ARP":
            opcode = int(list_of_frames[i]['hexa_frame'].replace(' ', '')[41:45], 16)
            arp_opcode = ""
            if opcode == 1:
                arp_opcode = "REQUEST"
            elif opcode == 2:
                arp_opcode = "REPLY"
            list_of_frames[i]['arp_opcode'] = arp_opcode
            arp_list.append(list_of_frames[i])
    return arp_list


def divide_to_pairs(arp_list):
    arp_request = []
    arp_reply = []
    for packet in arp_list:
        if packet['arp_opcode'] == "REQUEST":
            arp_request.append(packet)
        else:
            arp_reply.append(packet)

    arp_comlete_list = []
    arp_uncomplete_list = []
    for i in range(0, len(arp_request), 1):
        for j in range(0, len(arp_reply), 1):
            if 'is_used' not in arp_request[i]:
                arp_request[i]['is_used'] = False
            if 'is_used' not in arp_reply[j]:
                arp_reply[j]['is_used'] = False
            if arp_request[i]['is_used'] is True or arp_reply[j]['is_used'] is True:
                continue
            if arp_request[i]['src_ip'] == arp_reply[j]['dst_ip'] and arp_request[i]['dst_ip'] == arp_reply[j]['src_ip']:
                arp_comlete_list.append(arp_request[i])
                arp_comlete_list.append(arp_reply[j])
                arp_request[i]['is_used'] = True
                arp_reply[j]['is_used'] = True
                break

    for packet in arp_request:
        if packet['is_used'] is False:
            arp_uncomplete_list.append(packet)

    for packet in arp_comlete_list:
        packet.pop('is_used')

    for packet in arp_uncomplete_list:
        packet.pop('is_used')

    return arp_comlete_list, arp_uncomplete_list


def completed_to_groups_by_dst_ip(arp_comlete_list):
    grouped_data = {}
    for i in range(0, len(arp_comlete_list), 1):
        dst_ip = arp_comlete_list[i]['dst_ip']
        src_ip = arp_comlete_list[i]['src_ip']
        if arp_comlete_list[i]['arp_opcode'] == "REQUEST":
            if dst_ip in grouped_data:
                grouped_data[dst_ip].append(arp_comlete_list[i])
            if src_ip in grouped_data:
                grouped_data[src_ip].append(arp_comlete_list[i])
            else:
                grouped_data[dst_ip] = [arp_comlete_list[i]]
        else:
            if src_ip in grouped_data:
                grouped_data[src_ip].append(arp_comlete_list[i])
            elif dst_ip in grouped_data:
                grouped_data[dst_ip].append(arp_comlete_list[i])

    grouped_list = [packet_list for packet_list in grouped_data.values()]
    return grouped_list


def arp_to_yaml(list_of_frames):
    sort_arps = arp_sort(list_of_frames)
    arp_comlete_list, arp_uncomplete_list = divide_to_pairs(sort_arps)
    grouped_completed_list = completed_to_groups_by_dst_ip(arp_comlete_list)

    list_of_complete = []
    list_of_uncomplete = []
    file_path = "./output/arp.yaml"
    with open(file_path, 'w') as file:
        count_complete = 1
        count_uncomplete = 1
        for i in range(0, len(grouped_completed_list), 1):
            dictionary_to_yaml = {
                'number_comm': count_uncomplete,
                'src_comm': grouped_completed_list[i][0]['src_ip'],
                'dst_comm': grouped_completed_list[i][0]['dst_ip'],
                'packets': grouped_completed_list[i]
            }
            count_uncomplete += 1
            list_of_complete.append(dictionary_to_yaml)

        for i in range(0, len(arp_uncomplete_list), 1):
            dictionary_to_yaml = {
                'number_comm': count_uncomplete,
                'packets': arp_uncomplete_list[i]
            }
            count_uncomplete += 1
            list_of_uncomplete.append(dictionary_to_yaml)

        final_dict = {
            'name': 'PKS2023/24',
            'pcap_name': filename,
            'filter_name': 'ARP',
        }
        if arp_comlete_list:
            final_dict['complete_comms'] = list_of_complete
        if arp_uncomplete_list:
            final_dict['partial_comms'] = list_of_uncomplete
        yaml = ruamel.yaml.YAML()
        yaml.dump(final_dict, file)


def yaml_packets(packets):
    file_path = "./output/protocols.yaml"
    dict_list = []
    with open(file_path, 'w') as yaml_file:
        for i in range(0, len(packets), 1):
            str_hexa = hex_format(bytes.fromhex(packets[i]))
            result_dict = {
                'frame_number': i + 1,
                'len_frame_pcap': find_len_frame_pcap(packets[i]),
                'len_frame_medium': find_len_frame_medium(packets[i]),
                'frame_type': find_frame_type(packets[i]),
                'src_mac': find_src_mac(packets[i]),
                'dst_mac': find_dst_mac(packets[i]),
            }

            if find_frame_type(packets[i]) == Ethernet_II:
                result_dict['ether_type'] = find_eth_protocol(packets[i])
                if find_eth_protocol(packets[i]) == "IPv4":
                    result_dict['src_ip'] = find_source_ip(packets[i])
                    result_dict['dst_ip'] = find_dst_ip(packets[i])
                    result_dict['protocol'] = find_nested_protocol_ipv4(packets[i])
                    if (find_nested_protocol_ipv4(packets[i]) == "TCP" or
                            find_nested_protocol_ipv4(packets[i]) == "UDP"):
                        if find_app_protocol(packets[i]) != "":
                            result_dict['app_protocol'] = find_app_protocol(packets[i])
                        result_dict['src_port'] = find_src_port(packets[i])
                        result_dict['dst_port'] = find_dst_port(packets[i])
                if find_eth_protocol(packets[i]) == "ARP":
                    result_dict['src_ip'] = find_source_ip(packets[i])
                    result_dict['dst_ip'] = find_dst_ip(packets[i])

            if find_frame_type(packets[i]) == IEEE_LCC:
                result_dict['sap'] = find_ieee_sap(packets[i])
            if find_frame_type(packets[i]) == IEEE_LCC_SNAP:
                result_dict['pid'] = find_ieee_pid(packets[i])
            result_dict['hexa_frame'] = LiteralScalarString(str_hexa)
            dict_list.append(result_dict)

        packets = {
            'name': 'PKS2023/24',
            'pcap_name': filename,
            'packets': dict_list,
            'ipv4_senders': count_ips(packets),
            'max_send_packets_by': most_popular_ip(count_ips(packets))
        }
        yaml = ruamel.yaml.YAML()
        yaml.dump(packets, yaml_file)
        return dict_list


filename = input("Enter a filename: ")
# filename = "./pcap/trace-12.pcap"


def main():
    packets = read_pcap_to_list(filename)
    list_of_frames = yaml_packets(packets)
    while True:
        print("1 - analyze protocols TCP")
        print("2 - analyze protocols TFTP")
        print("3 - analyze protocols ICMP")
        print("4 - analyze protocols ARP")
        print("e - exit")
        choice = input("Enter your choice: ")
        if choice == "1":
            additional_choice = input("Enter protocol: ")
            print_completed_communications(list_of_frames, additional_choice)
        elif choice == "2":
            tftp_to_yaml(list_of_frames)
        elif choice == "3":
            icmp_to_yaml(list_of_frames)
        elif choice == "4":
            arp_to_yaml(list_of_frames)
        elif choice == "e":
            break


if __name__ == "__main__":
    main()
