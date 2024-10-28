#!/usr/bin/python3
import sys
import struct
import wrapper
import threading
import time
import os
from wrapper import recv_from_any_link, send_to_link, get_switch_mac, get_interface_name

def parse_ethernet_header(data):
    # Unpack the header fields from the byte array
    #dest_mac, src_mac, ethertype = struct.unpack('!6s6sH', data[:14])
    dest_mac = data[0:6]
    src_mac = data[6:12]
    
    # Extract ethertype. Under 802.1Q, this may be the bytes from the VLAN TAG
    ether_type = (data[12] << 8) + data[13]

    vlan_id = -1
    # Check for VLAN tag (0x8100 in network byte order is b'\x81\x00')
    if ether_type == 0x8200:
        vlan_tci = int.from_bytes(data[14:16], byteorder='big')
        vlan_id = vlan_tci & 0x0FFF  # extract the 12-bit VLAN ID
        ether_type = (data[16] << 8) + data[17]

    return dest_mac, src_mac, ether_type, vlan_id

def create_vlan_tag(vlan_id):
    # 0x8100 for the Ethertype for 802.1Q
    # vlan_id & 0x0FFF ensures that only the last 12 bits are used
    return struct.pack('!H', 0x8200) + struct.pack('!H', vlan_id & 0x0FFF)

def send_bdpu_every_sec(root_bridge_ID, own_bridge_ID, interface_object, interfaces):
    while True:
        # TODO Send BDPU every second if necessary
        if root_bridge_ID == own_bridge_ID:
            length = 416     
            dest_mac = bytes.fromhex("0180C2000000")             # 6b
            src_mac = get_switch_mac()                           # 6b
            llc_length = struct.pack('!H', length)               # 2b
            llc_header = bytes.fromhex("424203")                 # 3b
            protocol_id = bytes.fromhex("0000")                  # 2b
            protocol_version_id = bytes.fromhex("00")            # 1b
            bpdu_type = bytes.fromhex("00")                      # 1b
            flags = bytes.fromhex("00")                          # 1b
            root_id = struct.pack('!Q', int(root_bridge_ID))     # 8b
            root_path_cost = bytes.fromhex("00000000")           # 4b
            bridge_id = struct.pack('!Q', int(root_bridge_ID))   # 8b
            # port_ID                                            # 2b
            message_age = struct.pack('!H', 2)                   # 2b
            max_age = struct.pack('!H', 20)                      # 2b
            hello_time = struct.pack('!H', 2)                    # 2b
            forward_delay = struct.pack('!H', 15)                # 2b
            for i in interfaces:
                if interface_object[i].vlan == -2:
                    port_id = struct.pack('!H', i)
                    data = (
                        dest_mac + src_mac + llc_length + llc_header +
                        protocol_id + protocol_version_id + bpdu_type + flags +
                        root_id + root_path_cost + bridge_id + port_id +
                        message_age + max_age + hello_time + forward_delay
                    )
                    send_to_link(i, length, data)

        # Send BPDU on all trunk ports with:
        #     root_bridge_ID = own_bridge_ID
        #     sender_bridge_ID = own_bridge_ID
        #     sender_path_cost = 0
        
        time.sleep(1)

def receive_bdpu_frame(length, data, root_bridge_ID, own_bridge_ID, cost, interface_object, interfaces, interface):
    bdpu_root_id = int.from_bytes(data[22:30], byteorder='big')
    bdpu_root_cost = int.from_bytes(data[30:34], byteorder='big')
    bdpu_bridge_id = int.from_bytes(data[34:42], byteorder='big')
    root_port = int.from_bytes(data[42:44], byteorder='big')
    is_root = False

    if root_bridge_ID == own_bridge_ID:
        is_root = True

    if bdpu_root_id < root_bridge_ID:
        root_bridge_ID = bdpu_root_id
        cost = bdpu_root_cost + 10
    
        if is_root == True:
            for i in interfaces:
                if interface_object[i].vlan == -2:
                    interface_object[i].status = 0

        if interface_object[root_port].status == 0:
            interface_object[root_port].status = 1
        
        for i in interfaces:
            print(interface_object[i].vlan)
            if interface_object[i].vlan == -2 and i != root_port:
                data_mutable = bytearray(data)
                data_mutable[34:42] = struct.pack('!Q', own_bridge_ID)
                data_mutable[42:44] = struct.pack('!H', cost)
                send_to_link(i, length, bytes(data_mutable))
    elif bdpu_root_id == root_bridge_ID:
        if interface == root_port and bdpu_root_cost + 10 < cost:
            cost = bdpu_root_cost + 10
        elif interface != root_port:
            if bdpu_root_cost > cost:
                interface_object[interface].status = 1
    elif bdpu_bridge_id == own_bridge_ID:
        interface_object[interface].status = 0

    if own_bridge_ID == root_bridge_ID:
        for i in interfaces:
            interface_object[i].status = 1

    return root_bridge_ID, own_bridge_ID, cost


def parse_configure(switch_id):
    print(switch_id)
    file_path = os.path.join("configs", f"switch{switch_id}.cfg")
    f = open(file_path, "r")
    priority = f.readline().strip()
    vlan_id_table = {}
    for line in f:
        name, vlan = line.strip().split(" ", 1)
        vlan_id = -2
        if vlan != "T":
            vlan_id = int(vlan)
        vlan_id_table[name] = vlan_id
    
    return priority, vlan_id_table

def add_vlan_tag(vlan_id, data, length):
    return data[0:12] + create_vlan_tag(vlan_id) + data[12:], length + 32

def remove_vlan_tag(data, length):
    return data[0:12] + data[16:], length - 32

def get_vlan_from_source(interface, vlan_id_table, vlan, data, length):
    if vlan == -1:
        return vlan_id_table[get_interface_name(interface)], data, length
    else:
        data, length = remove_vlan_tag(data, length)
        return vlan, data, length

def send_frame(interface, length, data, interface_object, vlan):
    if interface_object[interface].status == 0:
        return

    vlan_dest = interface_object[interface].vlan
    if vlan_dest == -2:
        data, length = add_vlan_tag(vlan, data, length)
        send_to_link(interface, length, data)
    elif vlan_dest == vlan:
        send_to_link(interface, length, data)

def receive_frame(dest_mac, src_mac, mac_table, length, data, interface_object, vlan_id, interfaces, interface):
    if dest_mac != "ff:ff:ff:ff:ff:ff":
        mac_table[src_mac] = interface
        if dest_mac in mac_table:
            # send_to_link(mac_table[dest_mac], length, data)
            send_frame(mac_table[dest_mac], length, data, interface_object, vlan_id)
        else:
            for o in interfaces:
                if o != interface:
                    # send_to_link(o, length, data)
                    send_frame(o, length, data, interface_object, vlan_id)
    else:
        for o in interfaces:
                if o != interface:
                    # send_to_link(o, length, data)
                    send_frame(o, length, data, interface_object, vlan_id)

class Interface:
  def __init__(self, name, status, vlan):
    self.name = name
    self.status = status
    self.vlan = vlan

def main():
    # init returns the max interface number. Our interfaces
    # are 0, 1, 2, ..., init_ret value + 1
    switch_id = sys.argv[1]
    priority, vlan_id_table = parse_configure(switch_id)
    own_bridge_ID =  int(priority)
    root_bridge_ID = own_bridge_ID
    root_path_cost = 0
    
    print(priority)
    print(vlan_id_table)

    num_interfaces = wrapper.init(sys.argv[2:])
    print(num_interfaces)
    interfaces = range(0, num_interfaces)
    interface_object = {}
    for i in interfaces:
        if vlan_id_table[get_interface_name(i)] == -2:
            interface_object[i] = Interface(get_interface_name(i), 0, vlan_id_table[get_interface_name(i)])
        else:
            interface_object[i] = Interface(get_interface_name(i), 1, vlan_id_table[get_interface_name(i)])


    print("# Starting switch with id {}".format(switch_id), flush=True)
    print("[INFO] Switch MAC", ':'.join(f'{b:02x}' for b in get_switch_mac()))

    # Create and start a new thread that deals with sending BDPU
    t = threading.Thread(target=send_bdpu_every_sec, args=(root_bridge_ID, own_bridge_ID, interface_object, interfaces))
    t.start()

    # Printing interface names
    for i in interfaces:
        print(get_interface_name(i))

    mac_table = {}
    while True:
        # Note that data is of type bytes([...]).
        # b1 = bytes([72, 101, 108, 108, 111])  # "Hello"
        # b2 = bytes([32, 87, 111, 114, 108, 100])  # " World"
        # b3 = b1[0:2] + b[3:4].
        if own_bridge_ID == root_bridge_ID:
            for i in interfaces:
                interface_object[i].status = 1
        
        interface, data, length = recv_from_any_link()

        dest_mac, src_mac, ethertype, vlan_id = parse_ethernet_header(data)
        vlan_id, data, length = get_vlan_from_source(interface, vlan_id_table, vlan_id, data, length)

        # Print the MAC src and MAC dst in human readable format
        dest_mac = ':'.join(f'{b:02x}' for b in dest_mac)
        src_mac = ':'.join(f'{b:02x}' for b in src_mac)

        # Note. Adding a VLAN tag can be as easy as
        # tagged_frame = data[0:12] + create_vlan_tag(10) + data[12:]

        # print(f'Destination MAC: {dest_mac}')
        # print(f'Source MAC: {src_mac}')
        # print(f'EtherType: {ethertype}')

        # print("Received frame of size {} on interface {}".format(length, interface), flush=True)

        # print(vlan_id_table)

        # TODO: Implement forwarding with learning
        # TODO: Implement VLAN support
        # TODO: Implement STP support
        if dest_mac == "01:80:c2:00:00:00":
            root_bridge_ID, own_bridge_ID, root_path_cost = receive_bdpu_frame(length,
             data, root_bridge_ID, own_bridge_ID, root_path_cost, interface_object, interfaces, interface)
        else:
            receive_frame(dest_mac, src_mac, mac_table, length, data, interface_object, vlan_id, interfaces, interface)

        # data is of type bytes.
        # send_to_link(i, length, data)

if __name__ == "__main__":
    main()
