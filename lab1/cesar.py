import sys

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

def main():
    if len(sys.argv) != 3:
        print("Uso: python3 cesar.py <mensaje> <corrimiento>")
        return
    
    message = sys.argv[1]
    try:
        shift = int(sys.argv[2])
    except ValueError:
        print("El corrimiento debe ser un número entero.")
        return
    
    encrypted_message = encrypt_cesar(message, shift)
    print("Mensaje cifrado:", encrypted_message)

if __name__ == "__main__":
    main()



