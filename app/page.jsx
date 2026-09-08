'use client';

import { useState } from 'react';

export default function DecryptorPage() {
  const [file, setFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');

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
    setResult('');

    try {
      const response = await fetch('/api/decrypt', {
        method: 'POST',
        body: formData,
      });

      const data = await response.json();
      setResult(JSON.stringify(data, null, 2));
    } catch (error) {
      setResult(JSON.stringify({ error: error.message }, null, 2));
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(result);
    alert('Hasil konfigurasi berhasil disalin ke clipboard!');
  };

  return (
    <main className="min-h-screen flex flex-col items-center justify-center p-4 md:p-6">
      <div className="w-full max-w-xl bg-slate-900 border border-slate-800 rounded-2xl shadow-2xl p-6 md:p-8 backdrop-blur-md">
        
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

        {result && (
          <div className="mt-6">
            <div className="flex justify-between items-center mb-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-300">Hasil Konfigurasi:</label>
              <button 
                type="button" 
                onClick={copyToClipboard}
                className="bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs px-2.5 py-1 rounded-lg border border-slate-700 transition cursor-pointer font-medium"
              >
                Salin Teks
              </button>
            </div>
            <textarea 
              value={result} 
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
