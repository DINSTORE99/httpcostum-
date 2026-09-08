import './globals.css';

export const metadata = {
  title: 'Dark Tunnel Decryptor',
  description: 'Web tool profesional untuk membongkar file konfigurasi VPN (.dark)',
};

export default function RootLayout({ children }) {
  return (
    <html lang="id">
      <body className="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-slate-950">
        {children}
      </body>
    </html>
  );
}
