import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WebScanner — Vulnerability Scanner",
  description: "Authorized web vulnerability scanner for bug bounty use",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#0f1117] text-slate-200 antialiased flex flex-col">
        <div className="flex-1">{children}</div>
        <footer className="border-t border-slate-800 py-4 text-center text-xs text-slate-600">
          © {new Date().getFullYear()} By Zamiq Mustafayev
        </footer>
      </body>
    </html>
  );
}
