import type { Metadata } from "next";
import "./globals.css";
import { Providers } from "@/components/providers";

export const metadata: Metadata = {
  title: "Cyber-Security-Checker | SOC & Plataforma de Auditoria",
  description:
    "Plataforma de gerenciamento de vulnerabilidades, auditoria autorizada e recomendações técnicas de correção.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="pt-BR" suppressHydrationWarning>
      <body>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
