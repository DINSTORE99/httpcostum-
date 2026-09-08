import base64
import json
import msgpack
from http.server import BaseHTTPRequestHandler
import cgi
from Crypto.Cipher import AES

DT_KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
DT_IV = bytes.fromhex("232e39185523184a5723586242200e05")

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            form = cgi.FieldStorage(
                fp=self.rfile,
                headers=self.headers,
                environ={
                    'REQUEST_METHOD': 'POST',
                    'CONTENT_TYPE': self.headers.get('Content-Type'),
                }
            )
            
            if 'file' not in form:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Tidak ada file yang diunggah"}).encode())
                return

            fileitem = form['file']
            file_bytes = fileitem.file.read()
            
            encoded_data = file_bytes.decode('utf-8', errors='ignore').strip()
            clean_data = encoded_data.replace("-", "+").replace("_", "/")
            if pad := len(clean_data) % 4:
                clean_data += "=" * (4 - pad)
            
            raw_decrypted = base64.b64decode(clean_data)
            cipher = AES.new(DT_KEY_256, AES.MODE_CFB, iv=DT_IV, segment_size=128)
            decrypted_bytes = cipher.decrypt(raw_decrypted)
            
            unpacked_data = msgpack.unpackb(decrypted_bytes, raw=False)
            response_data = {"status": "success", "type": "Dark Tunnel", "data": unpacked_data}

            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode())

        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "error", "message": str(e)}).encode())
