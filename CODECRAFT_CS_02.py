from PIL import Image

def encrypt_image(image_path, operation, key):

    with Image.open(image_path) as img:
        img = img.convert('RGB')
        width, height = img.size
        pixels = img.load()

        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]

                if operation == 'swap':
                    pixels[x, y] = (b, g, r)
                elif operation == 'add':
                    pixels[x, y] = ((r + key) % 256, (g + key) % 256, (b + key) % 256)
                elif operation == 'subtract':
                    pixels[x, y] = ((r - key) % 256, (g - key) % 256, (b - key) % 256)
                elif operation == 'multiply':
                    pixels[x, y] = ((r * key) % 256, (g * key) % 256, (b * key) % 256)
                elif operation == 'divide':
                    pixels[x, y] = ((r // key) % 256, (g // key) % 256, (b // key) % 256)

        img.save('encrypted_image.png')

def decrypt_image(image_path, operation, key):

    with Image.open(image_path) as img:
        img = img.convert('RGB')
        width, height = img.size
        pixels = img.load()

        for x in range(width):
            for y in range(height):
                r, g, b = pixels[x, y]

                if operation == 'swap':
                    pixels[x, y] = (b, g, r)
                elif operation == 'add':
                    pixels[x, y] = ((r - key) % 256, (g - key) % 256, (b - key) % 256)
                elif operation == 'subtract':
                    pixels[x, y] = ((r + key) % 256, (g + key) % 256, (b + key) % 256)
                elif operation == 'multiply':
                    pixels[x, y] = ((r * pow(key, -1, 256)) % 256, (g * pow(key, -1, 256)) % 256, (b * pow(key, -1, 256)) % 256)
                elif operation == 'divide':
                    pixels[x, y] = ((r * key) % 256, (g * key) % 256, (b * key) % 256)

        img.save('decrypted_image.png')

def main():
    while True:
        print("Image Encryption Tool")
        print("1. Encrypt image")
        print("2. Decrypt image")
        print("3. Quit")

        choice = input("Enter your choice: ")

        if choice == '1':
            image_path = input("Enter the path to the image file: ")
            operation = input("Enter the operation to apply (swap, add, subtract, multiply, divide): ")
            key = int(input("Enter the key to use for the operation: "))
            encrypt_image(image_path, operation, key)
            print("Image encrypted successfully!")
        elif choice == '2':
            image_path = input("Enter the path to the encrypted image file: ")
            operation = input("Enter the operation that was applied to the image (swap, add, subtract, multiply, divide): ")
            key = int(input("Enter the key that was used for the operation: "))
            decrypt_image(image_path, operation, key)
            print("Image decrypted successfully!")
        elif choice == '3':
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()