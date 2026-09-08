export const metadata = {
  title: 'VPN Config Decryptor (.dark, .hc, .ehi)',
  description: 'Alat web multi-format untuk mendekripsi file Dark Tunnel, HTTP Custom, dan HTTP Injector.',
};

export default function RootLayout({ children }) {
  return (
    <html lang="id">
      <head>
        <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
      </head>
      <body className="bg-slate-950 text-slate-100 min-h-screen antialiased selection:bg-cyan-500 selection:text-slate-950">
        {children}
      </body>
    </html>
  );
}
