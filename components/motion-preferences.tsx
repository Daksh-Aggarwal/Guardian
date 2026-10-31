"use client";

import { MotionConfig, useReducedMotion } from "framer-motion";
import type { ReactNode } from "react";

export default function MotionPreferences({ children }: { children: ReactNode }) {
  const reduced = useReducedMotion();
  return (
    <MotionConfig reducedMotion="user" skipAnimations={!!reduced}>
      {children}
    </MotionConfig>
  );
}
