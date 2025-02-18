def caesar_cipher(text, shift, mode):

    result = ""

    for char in text:
        if char.isalpha():
            ascii_offset = 65 if char.isupper() else 97
            shift_amount = shift if mode == 'encrypt' else -shift
            result += chr((ord(char) - ascii_offset + shift_amount) % 26 + ascii_offset)
        else:
            result += char

    return result

def main():
    while True:
        print("Caesar Cipher Program")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. Quit")

        choice = input("Enter your choice: ")

        if choice == '1':
            text = input("Enter the text to encrypt: ")
            shift = int(input("Enter the shift value: "))
            encrypted_text = caesar_cipher(text, shift, 'encrypt')
            print(f"Encrypted text: {encrypted_text}")
        elif choice == '2':
            text = input("Enter the text to decrypt: ")
            shift = int(input("Enter the shift value: "))
            decrypted_text = caesar_cipher(text, shift, 'decrypt')
            print(f"Decrypted text: {decrypted_text}")
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()