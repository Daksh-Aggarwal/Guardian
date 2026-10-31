"use client";

import React from "react";
import { Component as GlowButton } from "@/components/ui/glow-button";

export default function GlowButtonDemo() {
  return (
    <div className="flex h-screen w-screen items-center justify-center bg-background text-foreground">
      <GlowButton />
    </div>
  );
}

