from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from PIL import Image
import numpy as np
import io
import os
from cryptography.fernet import Fernet
import base64
import hashlib

app = Flask(__name__)
CORS(app)

def process_user_key(user_key):
    """Process a user-provided key to make it compatible with Fernet."""
    # Hash the user-provided key and base64-encode it to ensure compatibility with Fernet
    hashed_key = hashlib.sha256(user_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(hashed_key)  # Output will be 32 bytes (44 characters in base64)
    return fernet_key

def encrypt_message(message, key):
    """Encrypt the message using a user-provided key with Fernet symmetric encryption."""
    fernet = Fernet(key)
    return fernet.encrypt(message.encode())

def decrypt_message(encrypted_message, key):
    """Decrypt the message using the user-provided key."""
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_message).decode()

def text_to_binary(data):
    """Convert bytes data to binary string."""
    return ''.join(format(byte, '08b') for byte in data)

def binary_to_text(binary_string):
    """Convert binary string to bytes data and decode to text."""
    chars = [binary_string[i:i+8] for i in range(0, len(binary_string), 8)]
    return bytes(int(char, 2) for char in chars)

def encode_image(image, binary_data):
    """Encode binary data into an image using LSB steganography."""
    pixels = np.array(image.convert('RGB'))
    pixels_flat = pixels.flatten()
    text_index = 0

    if len(binary_data) > len(pixels_flat):
        raise ValueError("Binary data is too large to encode in this image.")

    for i in range(len(pixels_flat)):
        if text_index < len(binary_data):
            pixel = pixels_flat[i]
            new_pixel = pixel & ~1 | int(binary_data[text_index])
            pixels_flat[i] = new_pixel
            text_index += 1
        else:
            break

    encoded_pixels = pixels_flat.reshape(pixels.shape)
    return Image.fromarray(encoded_pixels.astype('uint8'), 'RGB')

def decode_image(encoded_image):
    """Decode binary data from an image using LSB steganography."""
    pixels = np.array(encoded_image.convert('RGB'))
    pixels_flat = pixels.flatten()
    binary_data = ''.join(str(pixel & 1) for pixel in pixels_flat)
    
    # Stop at the end delimiter (used here as '1111111111111110')
    delimiter = '1111111111111110'
    if delimiter in binary_data:
        binary_data = binary_data[:binary_data.index(delimiter)]
    else:
        raise ValueError("End delimiter not found in the encoded image.")
    return binary_data

@app.route('/encode', methods=['POST'])
def encode():
    try:
        # Ensure all required data is present
        if 'image' not in request.files:
            return jsonify({"error": "Image file not provided"}), 400
        if 'text' not in request.form:
            return jsonify({"error": "Text message not provided"}), 400
        if 'key' not in request.form:
            return jsonify({"error": "Secret key not provided"}), 400

        # Get image, text, and user-provided key from the request
        image_file = request.files['image']
        text = request.form['text']
        user_key = request.form['key']

        # Process the user-provided key to ensure it's compatible with Fernet
        fernet_key = process_user_key(user_key)

        # Encrypt the message using the processed key
        encrypted_message = encrypt_message(text, fernet_key)
        binary_data = text_to_binary(encrypted_message) + '1111111111111110'

        # Encode the message into the image
        image = Image.open(image_file.stream)
        encoded_image = encode_image(image, binary_data)

        # Prepare image for output
        output = io.BytesIO()
        encoded_image.save(output, format="PNG")
        output.seek(0)

        return send_file(output, mimetype='image/png', as_attachment=True, download_name="encoded_image.png")

    except Exception as e:
        print(f"Encoding error: {e}")
        return jsonify({"error": f"Error encoding the image: {str(e)}"}), 400

@app.route('/decode', methods=['POST'])
def decode():
    try:
        # Get image and the user-provided key from the request
        if 'image' not in request.files:
            return jsonify({"error": "Encoded image file not provided"}), 400
        if 'key' not in request.form:
            return jsonify({"error": "Secret key not provided"}), 400

        image_file = request.files['image']
        user_key = request.form['key']

        # Process the user-provided key to ensure it's compatible with Fernet
        fernet_key = process_user_key(user_key)

        # Decode binary data from the image
        encoded_image = Image.open(image_file.stream)
        binary_data = decode_image(encoded_image)
        
        # Convert binary data back to text
        encrypted_message = binary_to_text(binary_data)
        
        # Decrypt the message
        hidden_message = decrypt_message(encrypted_message, fernet_key)

        return jsonify({"hidden_message": hidden_message})

    except Exception as e:
        print(f"Decoding error: {e}")  # Log specific error details
        return jsonify({"error": f"Failed to decode the image: {str(e)}"}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get("PORT", 5000)))
    # app.run(debug=True)
