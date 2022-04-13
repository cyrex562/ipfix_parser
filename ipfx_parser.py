import os
import sys
import socket
import struct

UDP_IP = "0.0.0.0"
UDP_PORT = 51212


def run() -> int:

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(0xFFFF)

        ptr = 0
        # parse data
        # IPFIX message header
        #  0 (2B): version number, currently 0x000a
        version = data[ptr : ptr + 2]
        ptr += 2
        #  16 (2B): length, tot len of message in bytes including header and sets
        length = data[ptr : ptr + 2]
        ptr += 2
        #  32 (4B): export time, num of seconds since epoch
        timestamp = data[ptr : ptr + 4]
        ptr += 4
        #  64 (4B): sequence number,
        seq_num = data[ptr : ptr + 4]
        ptr += 4
        #  96 (4B): observation domain ID, exporter ID
        domain_id = data[ptr : ptr + 4]

        print(
            f"""IPFIX message header
        version: {version}
        length: {length}
        timestamp: {timestamp}
        seq_num: {seq_num}
        domain_id: {domain_id}"""
        )

    return 0


if __name__ == "__main__":
    sys.exit(run())
