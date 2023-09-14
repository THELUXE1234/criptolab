#!/usr/bin/env python3
import sys
import time
from scapy.all import *

def encrypt_cesar(message, shift):
    encrypted_message = ""
    for char in message:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            encrypted_char = chr((ord(char) - ascii_offset + shift) % 26 + ascii_offset)
            encrypted_message += encrypted_char
        else:
            encrypted_message += char
    return encrypted_message

def generate_icmp_packet(data, identifier, sequence_number):
    payload = data.encode('utf-8')
    icmp_data =payload
    icmp_data += b'\x00'*7
    icmp_data += b'\x10\x11\x12\x13\x14\x15\x16\x17'  # Data from 0x10 to 0x17
    icmp_data += b'\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'  # Data from 0x18 to 0x1f
    icmp_data += b'\x20\x21\x22\x23\x24\x25\x26\x27'  # Data from 0x20 to 0x27
    icmp_data += b'\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f'  # Data from 0x28 to 0x2f
    icmp_data += b'01234567'  # Terminating data
    packet = IP(dst="8.8.8.8") / ICMP(type=8, code=0, id=identifier, seq=sequence_number) / Raw(load=icmp_data)
    return packet

def send_icmp_packets(message):
    identifier =  os.getpid() & 0xFFFF
    sequence_number = 1
    
    for char in message:
        packet = generate_icmp_packet(char, identifier, sequence_number)
        send(packet, verbose=False)
        sequence_number += 1
        time.sleep(1)  # Delay between packets

def main():
    if len(sys.argv) != 2:
        print("Usage: sudo python3 icmp.py <message>")
        sys.exit(1)
    
    message = sys.argv[1]
    encrypted = encrypt_cesar(message,9)
    send_icmp_packets(encrypted)
    print(f"Sent ICMP packets for message: '{encrypted}'-> '{message}'")

if __name__ == "__main__":
    main()

