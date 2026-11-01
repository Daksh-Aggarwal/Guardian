"use client";

import { useEffect, useRef, useState } from "react";
import { useRouter } from "next/navigation";
import { getSupabase } from "@/lib/supabase";

export default function CallbackPage() {
  const router = useRouter();
  const [error, setError] = useState("");
  const exchange = useRef<Promise<unknown> | null>(null);
  useEffect(() => {
    let active = true;
    const url = new URL(window.location.href);
    const code = url.searchParams.get("code");
    let client;
    try {
      client = getSupabase();
    } catch {
      setError("Check the public Supabase configuration in .env and rebuild.");
      return;
    }
    if (!code || url.searchParams.has("error") || !client) {
      setError(
        "GitHub authorization did not complete. Return to your account and try again.",
      );
      return;
    }
    if (!exchange.current)
      exchange.current = client.auth
        .exchangeCodeForSession(code)
        .then(({ error: failure }) => {
          if (failure) throw failure;
        });
    exchange.current
      .then(() => {
        if (active) {
          window.history.replaceState({}, "", "/auth/callback");
          router.replace("/account");
        }
      })
      .catch(() => {
        if (active)
          setError(
            "Authorization code expired or could not be verified. Sign in again.",
          );
      });
    return () => {
      active = false;
    };
  }, [router]);
  return (
    <main className="account-shell">
      <h1>Connecting your account</h1>
      <p role={error ? "alert" : "status"}>
        {error || "Finishing GitHub sign-in…"}
      </p>
      {error && <a href="/account">Return to DevGuardian</a>}
    </main>
  );
}
