import base64
import json
import msgpack
import zipfile
import io
from http.server import BaseHTTPRequestHandler
import cgi
from Crypto.Cipher import AES, ChaCha20

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

def decrypt_http_custom(file_bytes):
    """
    Menangani ekstraksi file .hc (HTTP Custom)
    """
    try:
        # Cek apakah file berupa ZIP (karena beberapa versi .hc adalah arsip terenkripsi)
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
                    "type": "HTTP Custom (.hc) - ZIP Container",
                    "files_inside": file_list,
                    "data": extracted_contents
                }
        
        # Jika bukan ZIP, coba parsing teks mentah atau cari pola JSON di dalam byte
        raw_text = file_bytes.decode('utf-8', errors='ignore')
        
        # Coba cari apakah ada struktur JSON tersembunyi
        start_idx = raw_text.find('{')
        end_idx = raw_text.rfind('}')
        if start_idx != -1 and end_idx != -1:
            try:
                json_part = json.loads(raw_text[start_idx:end_idx+1])
                return {
                    "status": "success",
                    "type": "HTTP Custom (.hc) - Parsed JSON",
                    "data": json_part
                }
            except:
                pass

        return {
            "status": "success",
            "type": "HTTP Custom (.hc) - Encrypted Payload",
            "message": "File ini menggunakan enkripsi privat versi HTTP Custom terbaru. Memerlukan key khusus versi app terkait untuk membongkar byte-nya secara penuh.",
            "raw_preview": raw_text[:500] + "..." if len(raw_text) > 500 else raw_text
        }
    except Exception as e:
        return {"status": "error", "message": f"Gagal memproses file .hc: {str(e)}"}

def decrypt_http_injector(file_bytes):
    """
    Menangani ekstraksi file .ehi (HTTP Injector)
    """
    try:
        raw_text = file_bytes.decode('utf-8', errors='ignore')
        
        # HTTP Injector seringkali menyimpan data konfigurasi dengan awalan header tertentu atau format base64
        if "NPVTSUB1" in raw_text or "NPVT1" in raw_text:
            return {
                "status": "success",
                "type": "HTTP Injector (.ehi) - Submitter Config",
                "content": raw_text
            }

        return {
            "status": "success",
            "type": "HTTP Injector (.ehi) - Encrypted Container",
            "message": "File .ehi terkunci oleh password/HWID atau enkripsi internal HTTP Injector.",
            "raw_preview": raw_text[:500] + "..." if len(raw_text) > 500 else raw_text
        }
    except Exception as e:
        return {"status": "error", "message": f"Gagal memproses file .ehi: {str(e)}"}

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
                response_data = decrypt_http_custom(file_bytes)
            elif filename.endswith('.ehi'):
                response_data = decrypt_http_injector(file_bytes)
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
