export const metadata = {
  title: 'Dark Tunnel Decryptor',
  description: 'Web tool profesional untuk membongkar file konfigurasi VPN (.dark)',
};

export default function RootLayout({ children }) {
  return (
    <html lang="id">
      <head>
        {/* Tailwind CSS CDN v4 agar langsung aktif di Vercel tanpa proses build CSS */}
        <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
      </head>
      <body className="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-slate-950">
        {children}
      </body>
    </html>
  );
}
