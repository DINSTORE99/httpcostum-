'use client';

import { useState } from 'react';

export default function DecryptorPage() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [responsedata, setResponseData] = useState(null);
  const [rawResult, setRawResult] = useState('');

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      alert('Pilih file konfigurasi terlebih dahulu!');
      return;
    }

    const formData = new FormData();
    formData.append('file', file);

    setLoading(true);
    setResponseData(null);
    setRawResult('');

    try {
      const response = await fetch('/api/decrypt', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();
      setResponseData(data);
      setRawResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setRawResult(JSON.stringify({ error: error.message }, null, 2));
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    alert('Berhasil disalin ke clipboard!');
  };

  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-4 md:p-6">
      <div className="w-full max-w-2xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 md:p-8 backdrop-blur-md">
        
        <div className="text-center mb-6">
          <h1 className="text-xl md:text-2xl font-extrabold tracking-wider text-cyan-400">VPN CONFIG DECRYPTOR</h1>
          <p className="text-slate-400 text-xs md:text-sm mt-1">Support file: <span className="text-cyan-300 font-semibold">.dark</span> | <span className="text-cyan-300 font-semibold">.hc</span> | <span className="text-cyan-300 font-semibold">.ehi</span></p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-slate-300 mb-2">Pilih File Config (.dark / .hc / .ehi)</label>
            <input 
              type="file" 
              onChange={handleFileChange} 
              required
              className="w-full text-xs text-slate-400 file:mr-4 file:py-2.5 file:px-4 file:rounded-xl file:border-0 file:text-xs file:font-bold file:bg-cyan-500 file:text-slate-950 hover:file:bg-cyan-400 file:cursor-pointer cursor-pointer bg-slate-950 border border-slate-800 rounded-xl p-2 transition"
            />
          </div>

          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-3 px-4 bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold rounded-xl transition duration-200 shadow-lg shadow-cyan-500/20 cursor-pointer disabled:opacity-50 text-sm"
          >
            {loading ? 'Sedang Memproses...' : 'Bongkar File (Decrypt)'}
          </button>
        </form>

        {loading && (
          <div className="text-center my-5">
            <p className="text-cyan-400 animate-pulse text-xs font-medium">Mendekripsi parameter file...</p>
          </div>
        )}

        {responsedata && responsedata.status === 'success' && responsedata.data && responsedata.data.Config && (
          <div className="mt-6 space-y-4">
            <div className="bg-slate-950 border border-slate-800 rounded-xl p-4">
              <h2 className="text-sm font-bold text-cyan-400 mb-3 uppercase tracking-wider">Detail Konfigurasi</h2>
              
              {/* Nama Config */}
              <div className="mb-3">
                <span className="text-xs text-slate-400 block">Nama Config:</span>
                <span className="text-sm font-semibold text-emerald-400">{responsedata.data.Config.name}</span>
              </div>

              {/* Proxy */}
              <div className="mb-3">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs text-slate-400">Proxy:</span>
                  <button onClick={() => copyToClipboard(responsedata.data.Config.proxy)} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded hover:bg-slate-700">Salin</button>
                </div>
                <input type="text" readOnly value={responsedata.data.Config.proxy} className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 font-mono" />
              </div>

              {/* SSH Field */}
              <div className="mb-3">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs text-slate-400">SSH Account / Server:</span>
                  <button onClick={() => copyToClipboard(responsedata.data.Config.sshField)} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded hover:bg-slate-700">Salin</button>
                </div>
                <input type="text" readOnly value={responsedata.data.Config.sshField} className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-slate-200 font-mono" />
              </div>

              {/* Payload */}
              <div className="mb-3">
                <div className="flex justify-between items-center mb-1">
                  <span className="text-xs text-slate-400">Payload:</span>
                  <button onClick={() => copyToClipboard(responsedata.data.Config.payload)} className="text-[10px] bg-slate-800 text-slate-300 px-2 py-0.5 rounded hover:bg-slate-700">Salin</button>
                </div>
                <textarea readOnly rows={4} value={responsedata.data.Config.payload} className="w-full bg-slate-900 border border-slate-800 rounded-lg p-2 text-xs text-cyan-300 font-mono resize-none" />
              </div>

              {/* Notes / Catatan Creator */}
              {responsedata.data.Config.notes && (
                <div>
                  <span className="text-xs text-slate-400 block mb-1">Catatan Pembuat (Notes):</span>
                  <div 
                    className="bg-slate-900 border border-slate-800 rounded-lg p-3 text-xs overflow-x-auto"
                    dangerouslySetInnerHTML={{ __html: responsedata.data.Config.notes }}
                  />
                </div>
              )}
            </div>
          </div>
        )}

        {/* Fallback JSON mentah jika format lain */}
        {rawResult && (!responsedata || responsedata.status !== 'success' || !responsedata.data?.Config) && (
          <div className="mt-6">
            <div className="flex justify-between items-center mb-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">Hasil Raw JSON:</label>
              <button 
                type="button" 
                onClick={() => copyToClipboard(rawResult)}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-2.5 py-1 rounded-lg border border-slate-700 transition cursor-pointer font-medium"
              >
                Salin Teks
              </button>
            </div>
            <textarea 
              value={rawResult} 
              readOnly 
              rows={9}
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-xs text-emerald-400 font-mono focus:outline-none resize-none leading-relaxed"
            />
          </div>
        )}

      </div>
    </main>
  );
}
