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
      <body className="min-h-screen bg-[#0f1117] text-slate-200 antialiased">
        {children}
      </body>
    </html>
  );
}
