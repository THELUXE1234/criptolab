#!/usr/bin/env python3
import sys
from scapy.all import *
from colorama import Fore, Style  # Importar módulos necesarios de colorama

def decrypt_cesar(encrypted_message, shift):
    decrypted_message = ""
    for char in encrypted_message:
        if char.isalpha():
            ascii_offset = ord('a') if char.islower() else ord('A')
            decrypted_char = chr((ord(char) - ascii_offset - shift) % 26 + ascii_offset)
            decrypted_message += decrypted_char
        else:
            decrypted_message += char
    return decrypted_message

def analyze_icmp_packets(pcap_file):
    packets = rdpcap(pcap_file)
    encrypted_message = ""

    for packet in packets:
        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            icmp_data = packet[Raw].load
            encrypted_char = chr(icmp_data[0])
            encrypted_message += encrypted_char

    return encrypted_message

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 decrypt_icmp.py <pcap_file>")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    encrypted_message = analyze_icmp_packets(pcap_file)
    print("Encrypted Message:", encrypted_message)
    
    best_shift = None
    best_decrypted_message = None

    for shift in range(26):
        decrypted_message = decrypt_cesar(encrypted_message, shift)

        # Verificar si el mensaje decifrado parece ser coherente con el español
        if " " in decrypted_message and all(c.isalpha() or c.isspace() for c in decrypted_message):
            if best_shift is None:
                best_shift = shift
                best_decrypted_message = decrypted_message
            else:
                # Calcular el puntaje de coherencia (puedes mejorar este criterio)
                score = sum(1 for c in decrypted_message if c.lower() in "aeiouáéíóú")
                best_score = sum(1 for c in best_decrypted_message if c.lower() in "aeiouáéíóú")
                if score > best_score:
                    best_shift = shift
                    best_decrypted_message = decrypted_message

    if best_decrypted_message:
        print("Best Decryption:")
        for shift in range(26):
            decrypted_message = decrypt_cesar(encrypted_message, shift)
            if shift == best_shift:
                print(Fore.GREEN + f"Shift {shift:02}: {decrypted_message}" + Style.RESET_ALL)
            else:
                print(f"Shift {shift:02}: {decrypted_message}")
    else:
        print("No coherent decryption found.")

if __name__ == "__main__":
    main()
