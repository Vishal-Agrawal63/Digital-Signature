from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import webbrowser
from threading import Timer

app = Flask(__name__)
CORS(app)  

key = RSA.generate(2048)
private_key = key.export_key()
public_key = key.publickey().export_key()

@app.route('/')
def home():
    return render_template('digitalSignature.html')

@app.route('/sign', methods=['POST'])
def sign_message():
    data = request.json
    message = data.get('message')
    
    if not message:
        return jsonify({"error": "Message is required"}), 400
    
    # Sign the message
    hash_obj = SHA256.new(message.encode('utf-8'))
    signature = pkcs1_15.new(key).sign(hash_obj)
    
    return jsonify({
        "signature": signature.hex(),
        "public_key": public_key.decode('utf-8')
    })

@app.route('/verify', methods=['POST'])
def verify_signature():
    data = request.json
    message = data.get('message')
    signature_hex = data.get('signature')
    
    if not message or not signature_hex:
        return jsonify({"error": "Message and signature are required"}), 400
    
    # Verify the signature
    try:
        hash_obj = SHA256.new(message.encode('utf-8'))
        signature = bytes.fromhex(signature_hex)
        pkcs1_15.new(key.publickey()).verify(hash_obj, signature)
        return jsonify({"valid": True})
    except (ValueError, TypeError):
        return jsonify({"valid": False})

def open_browser():
    """Automatically open the HTML file in the browser."""
    webbrowser.open("http://127.0.0.1:5000/")

if __name__ == '__main__':
    Timer(1, open_browser).start()
    app.run(debug=True)
