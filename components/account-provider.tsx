"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import type { Session } from "@supabase/supabase-js";
import { getSupabase } from "@/lib/supabase";

const Context = createContext<{
  session: Session | null;
  loading: boolean;
  error: string;
  configured: boolean;
  signIn: () => Promise<void>;
  signOut: () => Promise<void>;
}>({
  session: null,
  loading: true,
  error: "",
  configured: false,
  signIn: async () => {},
  signOut: async () => {},
});

export function AccountProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [configured, setConfigured] = useState(false);
  useEffect(() => {
    let active = true;
    let unsubscribe: (() => void) | undefined;
    try {
      const client = getSupabase();
      setConfigured(!!client);
      if (!client) {
        setLoading(false);
        return;
      }
      client.auth
        .getSession()
        .then(({ data, error: failure }) => {
          if (!active) return;
          setSession(data.session);
          if (failure)
            setError(
              "Your account session could not be restored. Sign in again.",
            );
          setLoading(false);
        })
        .catch(() => {
          if (active) {
            setError("Could not restore your account session.");
            setLoading(false);
          }
        });
      const listener = client.auth.onAuthStateChange((_event, value) => {
        if (active) {
          setSession(value);
          setLoading(false);
        }
      });
      unsubscribe = () => listener.data.subscription.unsubscribe();
    } catch {
      setError(
        "Check the public Supabase settings in .env and rebuild the frontend.",
      );
      setLoading(false);
    }
    return () => {
      active = false;
      unsubscribe?.();
    };
  }, []);

  const signIn = useCallback(async () => {
    setError("");
    try {
      const client = getSupabase();
      if (!client)
        throw new Error(
          "Set the public Supabase URL and publishable key in .env, then restart the frontend.",
        );
      const { error: failure } = await client.auth.signInWithOAuth({
        provider: "github",
        options: {
          redirectTo: window.location.origin + "/auth/callback",
          scopes: "read:user user:email",
        },
      });
      if (failure) throw failure;
    } catch (problem) {
      setError(
        problem instanceof Error ? problem.message : "GitHub sign-in failed.",
      );
    }
  }, []);
  const signOut = useCallback(async () => {
    const client = getSupabase();
    if (!client) return;
    const { error: failure } = await client.auth.signOut({ scope: "local" });
    if (failure) {
      setError("Logout could not reach Supabase. Retry when connected.");
      return;
    }
    setSession(null);
    setError("");
  }, []);
  return (
    <Context.Provider
      value={{ session, loading, error, configured, signIn, signOut }}
    >
      {children}
    </Context.Provider>
  );
}

export function useAccount() {
  return useContext(Context);
}

export function AccountButton() {
  const { session, loading } = useAccount();
  return (
    <a href="/account" className="btn-secondary" aria-label="Guardian account">
      {loading ? "Account…" : session ? "My account" : "Sign in"}
    </a>
  );
}
