"use client";

import { useEffect } from "react";
import { MotionConfig, useReducedMotion } from "framer-motion";
import type { ReactNode } from "react";

export default function MotionPreferences({
  children,
}: {
  children: ReactNode;
}) {
  const reduced = useReducedMotion();

  useEffect(() => {
    // Unregister any stale service workers or rogue caches on localhost/127.0.0.1
    if (typeof window !== "undefined") {
      if ("serviceWorker" in navigator) {
        navigator.serviceWorker.getRegistrations().then((registrations) => {
          for (const reg of registrations) {
            reg.unregister();
          }
        });
      }
      if ("caches" in window) {
        caches.keys().then((names) => {
          for (const name of names) {
            caches.delete(name);
          }
        });
      }
    }
  }, []);

  return (
    <MotionConfig reducedMotion="user" skipAnimations={!!reduced}>
      {children}
    </MotionConfig>
  );
}
