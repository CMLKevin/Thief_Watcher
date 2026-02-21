import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Thief Watcher Command Center",
  description:
    "Professional blockchain incident response console for wallet tracing, exposure mapping, and escalation workflows.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
