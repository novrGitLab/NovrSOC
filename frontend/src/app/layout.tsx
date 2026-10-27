import type { Metadata } from "next";
import { Space_Grotesk, Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";
import { ThemeProvider } from "@/components/providers/ThemeProvider";
import { GoogleAuthProvider } from "@/components/providers/GoogleAuthProvider";

const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  variable: "--font-space-grotesk",
  display: "swap",
});

const inter = Inter({
  subsets: ["latin"],
  variable: "--font-inter",
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  subsets: ["latin"],
  variable: "--font-jetbrains-mono",
  display: "swap",
});

// The real production domain, confirmed live by curl — see sitemap.ts for how this was found
// (the first guess, novrsoc-frontend.onrender.com, 404s: that Render service was never deployed).
const SITE_URL = "https://novr-soc.vercel.app";
const DEFAULT_TITLE = "Novr VTEM — Your Security Stack, One Intelligent Platform | NovrSOC by Cybernovr";
const DEFAULT_DESCRIPTION = "Unify vulnerability management, threat intelligence, security monitoring, investigation and response through a vendor-agnostic Open XDR platform, engineered in Nigeria.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: DEFAULT_TITLE, template: "%s" },
  description: DEFAULT_DESCRIPTION,
  icons: { icon: "/novrsoc.jpg" },
  openGraph: {
    type: "website",
    siteName: "NovrSOC by Cybernovr",
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    url: SITE_URL,
    images: [{ url: "/novrsoc.jpg", width: 512, height: 512, alt: "NovrSOC by Cybernovr" }],
  },
  twitter: {
    card: "summary",
    title: DEFAULT_TITLE,
    description: DEFAULT_DESCRIPTION,
    images: ["/novrsoc.jpg"],
  },
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
      className={`${spaceGrotesk.variable} ${inter.variable} ${jetbrainsMono.variable}`}
    >
      <body>
        <ThemeProvider>
          <GoogleAuthProvider>{children}</GoogleAuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
