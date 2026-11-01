import MotionPreferences from "@/components/motion-preferences";
import SmoothScroll from "@/components/smooth-scroll";
import type { Metadata } from "next";
import "./globals.css";
import "./signal-fonts.css";
import "./account.css";
import { AccountProvider } from "@/components/account-provider";
export const metadata: Metadata = {
  title: "Guardian — Know what you trust.",
  description:
    "Evidence-based software supply-chain security. Inspect packages, understand behavior, and make informed decisions.",
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>
        <MotionPreferences>
          <AccountProvider><SmoothScroll>{children}</SmoothScroll></AccountProvider>
        </MotionPreferences>
      </body>
    </html>
  );
}
