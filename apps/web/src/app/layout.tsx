import type { Metadata } from "next";
import "./globals.css";
import { ThemeProvider } from "@/components/providers/ThemeProvider";

// Phase 2: the Google sign-in provider was removed. Its component was not carried into V2 (Google
// sign-in depended on a dropped legacy proxy). Sign-in is the V2 session login at /login.
export const metadata: Metadata = {
  title: "NovrSOC",
  description: "NovrSOC security operations platform",
  icons: { icon: "/novrsoc.jpg" },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      suppressHydrationWarning
    >
      <body>
        <ThemeProvider>{children}</ThemeProvider>
      </body>
    </html>
  );
}
