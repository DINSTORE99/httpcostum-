import base64
import json
import msgpack
import zipfile
import io
from http.server import BaseHTTPRequestHandler
import cgi
from Crypto.Cipher import AES

# Kunci Dark Tunnel (.dark)
DT_KEY_256 = b"$B&E)H@McQfThWmZq4t7w!z%C*F-JaNd"
DT_IV = bytes.fromhex("232e39185523184a5723586242200e05")

def decrypt_dark_tunnel(file_bytes):
    try:
        encoded_data = file_bytes.decode('utf-8', errors='ignore').strip()
        clean_data = encoded_data.replace("-", "+").replace("_", "/")
        if pad := len(clean_data) % 4:
            clean_data += "=" * (4 - pad)
        
        raw_decrypted = base64.b64decode(clean_data)
        cipher = AES.new(DT_KEY_256, AES.MODE_CFB, iv=DT_IV, segment_size=128)
        decrypted_bytes = cipher.decrypt(raw_decrypted)
        
        unpacked_data = msgpack.unpackb(decrypted_bytes, raw=False)
        return {"status": "success", "type": "Dark Tunnel (.dark)", "data": unpacked_data}
    except Exception as e:
        return {"status": "error", "message": f"Gagal decrypt Dark Tunnel: {str(e)}"}

def decrypt_http_custom_or_injector(file_bytes, ext):
    """
    Menangani ekstrak file container ZIP/Encrypted dari .hc (HTTP Custom) dan .ehi (HTTP Injector)
    """
    try:
        # File .hc dan .ehi umumnya berupa arsip ZIP atau terenkripsi lapis bawah
        if zipfile.is_zipfile(io.BytesIO(file_bytes)):
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as z:
                file_list = z.namelist()
                extracted_contents = {}
                for filename in file_list:
                    with z.open(filename) as f:
                        content = f.read().decode('utf-8', errors='ignore')
                        try:
                            extracted_contents[filename] = json.loads(content)
                        except:
                            extracted_contents[filename] = content
                
                return {
                    "status": "success",
                    "type": f"HTTP {'Custom (.hc)' if ext == '.hc' else 'Injector (.ehi)'} (ZIP Container)",
                    "files_inside": file_list,
                    "data": extracted_contents
                }
        else:
            # Jika file terkunci/terenkripsi penuh oleh algoritma aplikasi
            decoded_text = file_bytes.decode('utf-8', errors='ignore')
            return {
                "status": "success",
                "type": f"HTTP {'Custom (.hc)' if ext == '.hc' else 'Injector (.ehi)'} (Raw Payload)",
                "raw_preview": decoded_text[:1000] if len(decoded_text) > 1000 else decoded_text,
                "note": "File terkunci enkripsi privat versi aplikasi terkait. Menampilkan struktur raw/metadata."
            }
    except Exception as e:
        return {"status": "error", "message": f"Gagal membaca format {ext}: {str(e)}"}

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
            filename = fileitem.filename.lower()

            if filename.endswith('.dark'):
                response_data = decrypt_dark_tunnel(file_bytes)
            elif filename.endswith('.hc'):
                response_data = decrypt_http_custom_or_injector(file_bytes, '.hc')
            elif filename.endswith('.ehi'):
                response_data = decrypt_http_custom_or_injector(file_bytes, '.ehi')
            else:
                response_data = {"status": "error", "message": "Format file tidak didukung! Gunakan .dark, .hc, atau .ehi"}

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
