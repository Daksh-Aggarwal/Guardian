export type AccountAuth = {
  getSession: () => Promise<{
    data: { session: { access_token: string } | null };
    error: unknown;
  }>;
  refreshSession: () => Promise<{
    data: { session: { access_token: string } | null };
    error: unknown;
  }>;
};

export async function accountRequest<T>(
  auth: AccountAuth | null,
  path: string,
  options?: RequestInit,
): Promise<T> {
  if (!auth)
    throw new Error("Configure Supabase and sign in to connect your account.");
  if (!path.startsWith("/") || path.startsWith("//"))
    throw new Error("Invalid account API path.");
  let { data, error } = await auth.getSession();
  if (error || !data.session)
    throw new Error("Your account session expired. Sign in again.");
  for (let attempt = 0; attempt < 2; attempt++) {
    const headers = new Headers(options?.headers);
    headers.set("Authorization", `Bearer ${data.session!.access_token}`);
    const response = await fetch(`/api/account${path}`, {
      ...options,
      headers,
      cache: "no-store",
    });
    if (response.status === 401 && attempt === 0) {
      const refreshed = await auth.refreshSession();
      if (refreshed.error || !refreshed.data.session)
        throw new Error("Your account session expired. Sign in again.");
      data = refreshed.data;
      continue;
    }
    if (!response.ok) {
      let message =
        "Account service unavailable. Your local reports are unchanged.";
      try {
        const body: unknown = await response.json();
        if (
          body &&
          typeof body === "object" &&
          "detail" in body &&
          typeof body.detail === "string"
        )
          message = body.detail;
      } catch {
        /* A transport failure must remain visible. */
      }
      throw new Error(message);
    }
    return response.json() as Promise<T>;
  }
  throw new Error("Your account session expired. Sign in again.");
}
