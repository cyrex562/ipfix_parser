import os
import sys
import socket
import struct
import ipaddress
from typing import Tuple
import datetime

from requests import head

UDP_IP = "0.0.0.0"
UDP_PORT = 6343

HDR_PROTO_ETHERNET = 1
HDR_PROTO_TOKENBUS = 2
HDR_PROTO_TOKENRING = 3
HDR_PROTO_FDDI = 4
HDR_PROTO_FRAME_RELAY = 5
HDR_PROTO_X25 = 6
HDR_PROTO_PPP = 7
HDR_PROTO_SMDS = 8
HDR_PROTO_AAL5 = 9
HDR_PROTO_AAL5_IP = 10
HDR_PROTO_IPV4 = 11
HDR_PROTO_IPV6 = 12
HDR_PROTO_MPLS = 13
HDR_PROTO_POS = 14

FLOW_SAMP_TYPE_RAW = 1
FLOW_SAMP_TYPE_ETHER = 2
FLOW_SAMP_TYPE_IPV4 = 3
FLOW_SAMP_TYPE_IPV6 = 4
FLOW_SAMP_TYPE_EXT_SWITCH = 1001
FLOW_SAMP_TYPE_EXT_RTR = 1002
FLOW_SAMP_TYPE_EXT_GW = 1003
FLOW_SAMP_TYPE_EXT_USER = 1004
FLOW_SAMP_TYPE_EXT_URL = 1005
FLOW_SAMP_TYPE_EXT_MPLS = 1006
FLOW_SAMP_TYPE_EXT_NAT = 1007
FLOW_SAMP_TYPE_EXT_MPLS_TUN = 1008
FLOW_SAMP_TYPE_EXT_MPLS_VC = 1009
FLOW_SAMP_TYPE_EXT_MPLS_FTN = 1010
FLOW_SAMP_TYPE_EXT_MPLS_LDP_FEC = 1011
FLOW_SAMP_TYPE_EXT_VLAN = 1012


def bytes_to_str

def get_u32(buf: bytes, ptr: int) -> Tuple[int, int]:
    val = struct.unpack("!I", buf[ptr : ptr + 4])[0]
    new_ptr = ptr + 4
    return (val, new_ptr)


def run() -> int:

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(0xFFFF)
        data_len = len(data)
        ptr = 0

        # 0    4B    version
        version, ptr = get_u32(data, ptr)

        # 4    4B agent_address type
        agent_address_type, ptr = get_u32(data, ptr)

        # 8    4B-16B agent_address
        if agent_address_type == 1:
            # IPV4
            agent_address = ipaddress.IPv4Address(data[ptr : ptr + 4])
            ptr += 4
        elif agent_address_type == 2:
            # IPV6
            agent_address = ipaddress.IPv6Address(data[ptr : ptr + 16])
            ptr += 16
        else:
            sys.exit(f"unknown agent address type: {agent_address_type}")

        # 4B agent sub address
        sub_agent_id, ptr = get_u32(data, ptr)

        # 4B sequence number
        seq_num, ptr = get_u32(data, ptr)

        # 4B sys uptime
        sys_uptime_u32, ptr = get_u32(data, ptr)
        sys_uptime = str(datetime.timedelta(seconds=sys_uptime_u32 / 1000))

        num_samples, ptr = get_u32(data, ptr)

        # print datagram
        print(
            f"""
sFlow datagram:
    version: {version}
    agent address type: {agent_address_type}
    agent address: {str(agent_address)}
    sub agent ID: {sub_agent_id}
    seq #: {seq_num}
    system uptime: {sys_uptime}
    # samples: {num_samples}
        """
        )

        sampled = 0
        while sampled < num_samples:
            # parse sample records
            # 4B data format: 20 bits: SMI private enterprise code + 12 bits: structure format number
            data_format, ptr = get_u32(data, ptr)
            private_entprise_code = data_format >> 12
            sample_type = data_format & 0b00000000000000000000111111111111

            if sample_type == 1:  # flow sample
                # 4B sample length
                sample_length, ptr = get_u32(data, ptr)
                # 4B sample seq num
                sample_seq_num, ptr = get_u32(data, ptr)
                # 4B (1,3) src type + if index
                src_type_if_index, ptr = get_u32(data, ptr)
                src_type = src_type_if_index >> 24
                ifindex = src_type_if_index & 0x00FFFFFF
                # 4B sampling rate
                sampling_rate, ptr = get_u32(data, ptr)
                # 4B sample pool
                sample_pool, ptr = get_u32(data, ptr)
                # 4B drops
                drops, ptr = get_u32(data, ptr)
                # input interface
                in_interface_u32, ptr = get_u32(data, ptr)
                in_ifc_fmt = (
                    in_interface_u32 & 0b1100000000000000000000000000000000
                ) >> 30

                if in_ifc_fmt == 0:  # single interface
                    in_ifc_index = in_interface_u32 & 0b00111111111111111111111111111111
                    in_ifc_str = f"in interface index: {in_ifc_index}"
                elif in_ifc_fmt == 1:  # packet discarded
                    in_ifc_drop_reason_code = (
                        in_interface_u32 & 0b00111111111111111111111111111111
                    )
                    in_ifc_str = f"in interface drop reason: {in_ifc_drop_reason_code}"
                else:  # in_ifc_fmt == 2: # multiple dest interfaces
                    in_ifc_num_dest_interfaces = (
                        in_interface_u32 & 0b00111111111111111111111111111111
                    )
                    in_ifc_str = f"in i nterface num dest interfaces: {in_ifc_num_dest_interfaces}"

                # output interface
                out_interface_u32, ptr = get_u32(data, ptr)
                out_ifc_fmt = (
                    out_interface_u32 & 0b1100000000000000000000000000000000
                ) >> 30

                if out_ifc_fmt == 0:  # single interface
                    out_ifc_index = (
                        out_interface_u32 & 0b00111111111111111111111111111111
                    )
                    out_ifc_str = f"out interface index: {out_ifc_index}"
                elif out_ifc_fmt == 1:  # packet discarded
                    out_ifc_drop_reason_code = (
                        out_interface_u32 & 0b00111111111111111111111111111111
                    )
                    out_ifc_str = (
                        f"out interface drop reason: {out_ifc_drop_reason_code}"
                    )
                else:  # out_ifc_fmt == 2: # multiple dest interfaces
                    out_ifc_num_dest_interfaces = (
                        in_interface_u32 & 0b00111111111111111111111111111111
                    )
                    out_ifc_str = f"out interface num dest interfaces: {out_ifc_num_dest_interfaces}"

                flow_record_count, ptr = get_u32(data, ptr)

                flow_data_format, ptr = get_u32(data, ptr)
                private_entprise_code = flow_data_format >> 12
                flow_sample_type = flow_data_format & 0b00000000000000000000111111111111

                print(
                    f"""
    sample record:
        SMI private enterprise code: {private_entprise_code}
        struct format num: {sample_type}
        sample length: {sample_length}
        sample seq #: {sample_seq_num}
        src type: {src_type}
        if index: {ifindex}
        sampling rate: 1 / {sampling_rate}
        sample pool: {sample_pool}
        drops: {drops}
        in iface: {in_ifc_str}
        out iface: {out_ifc_str}
        record count: {flow_record_count}"""
                )

                if flow_sample_type == FLOW_SAMP_TYPE_RAW:  # raw
                    header_protocol, ptr = get_u32(data, ptr)
                    frame_len, ptr = get_u32(data, ptr)
                    stripped, ptr = get_u32(data, ptr)
                    frame_bytes = data[ptr : ptr + 128]

                    print(f"""
        header proto: {header_protocol}
        frame len: {frame_len}
        stripped: {stripped}
        """)

                    ptr += 128
                    if header_protocol == HDR_PROTO_ETHERNET:
                        pass
                    elif header_protocol == HDR_PROTO_TOKENBUS:
                        pass
                    elif header_protocol == HDR_PROTO_TOKENRING:
                        pass
                    elif header_protocol == HDR_PROTO_FDDI:
                        pass
                    elif header_protocol == HDR_PROTO_FRAME_RELAY:
                        pass
                    elif header_protocol == HDR_PROTO_X25:
                        pass
                    elif header_protocol == HDR_PROTO_PPP:
                        pass
                    elif header_protocol == HDR_PROTO_SMDS:
                        pass
                    elif header_protocol == HDR_PROTO_AAL5:
                        pass
                    elif header_protocol == HDR_PROTO_AAL5_IP:
                        pass
                    elif header_protocol == HDR_PROTO_IPV4:
                        pass
                    elif header_protocol == HDR_PROTO_IPV6:
                        pass
                    elif header_protocol == HDR_PROTO_MPLS:
                        pass
                    elif header_protocol == HDR_PROTO_POS:
                        pass
                    else:
                        sys.exit(f"unhandled header protocol: {header_protocol}")
                elif flow_sample_type == FLOW_SAMP_TYPE_ETHER:  # ethernet
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_IPV4:  # IPv4
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_IPV6:  # IPv6
                    pass
                elif (
                    flow_sample_type == FLOW_SAMP_TYPE_EXT_SWITCH
                ):  # extended switch data
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_EXT_RTR:  # extended router data
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_EXT_GW:  # extended gateway data
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_EXT_USER:  # extended user data
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_EXT_URL:  # extended URL data
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_EXT_MPLS:  # extended MPLS data
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_EXT_NAT:  # extended NAT data
                    pass
                elif (
                    flow_sample_type == FLOW_SAMP_TYPE_EXT_MPLS_TUN
                ):  # extended MPLS tunnel
                    pass
                elif flow_sample_type == FLOW_SAMP_TYPE_EXT_MPLS_VC:  # extended MPLS VC
                    pass
                elif (
                    flow_sample_type == FLOW_SAMP_TYPE_EXT_MPLS_FTN
                ):  # extended MPLS FTN
                    pass
                elif (
                    flow_sample_type == FLOW_SAMP_TYPE_EXT_MPLS_LDP_FEC
                ):  # extended MPLS LDP FEC
                    pass
                elif (
                    flow_sample_type == FLOW_SAMP_TYPE_EXT_VLAN
                ):  # extended VLAN tunnel info
                    pass
                else:
                    sys.exit(f"unknown flow sample type: {flow_sample_type}")

                

            elif sample_type == 2:  # counters sample
                # 4B sample length
                sample_length, ptr = get_u32(data, ptr)
                # 4B sample seq num
                sample_seq_num, ptr = get_u32(data, ptr)
                # 4B (1,3) src type + if index
                src_type_if_index, ptr = get_u32(data, ptr)
                src_type = src_type_if_index >> 24
                ifindex = src_type_if_index & 0x00FFFFFF
                counter_record_count, ptr = get_u32(data, ptr)

                print(
                    f"""
    sample record:
        SMI private enterprise code: {private_entprise_code}
        struct format num: {sample_type}
        sample length: {sample_length}
        sample seq #: {sample_seq_num}
        src type: {src_type}
        if index: {ifindex}
        record count: {counter_record_count}
                """
                )

            else:  #
                sys.exit(f"unhandled sample type {sample_type}")

            break

    return 0


if __name__ == "__main__":
    sys.exit(run())
