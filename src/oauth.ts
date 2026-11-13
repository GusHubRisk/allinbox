// Microsoft OAuth (device-code flow) for Outlook.com / Hotmail / Live and Microsoft 365 over IMAP XOAUTH2.
// Public client: no secret ships. The client id comes from the user's own Entra app registration
// (ALLINBOX_MS_CLIENT_ID or config.microsoft.clientId). The refresh token lives in the OS keychain,
// in the same slot an app password would use; access tokens live only in memory.

export const MS_SCOPE = 'https://outlook.office.com/IMAP.AccessAsUser.All offline_access';
const AUTHORITY = 'https://login.microsoftonline.com';
const REFRESH_MARGIN_MS = 5 * 60_000;

export interface MsTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
}

export interface DeviceCodePrompt {
  userCode: string;
  verificationUri: string;
  message: string;
}

type Fetch = typeof fetch;

/** `consumers` for personal accounts, `organizations` for Microsoft 365, `common` accepts both. */
export const tenantFor = (email: string): string =>
  /@(outlook|hotmail|live|msn)\.[a-z.]+$/i.test(email) ? 'consumers' : 'organizations';

async function post(url: string, body: Record<string, string>, f: Fetch): Promise<Record<string, unknown>> {
  const res = await f(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams(body).toString(),
  });
  return (await res.json()) as Record<string, unknown>;
}

const toTokens = (json: Record<string, unknown>, now: number, previousRefresh?: string): MsTokens => {
  if (typeof json.access_token !== 'string') {
    throw new Error(`Microsoft login failed: ${String(json.error_description ?? json.error ?? 'no access token')}`);
  }
  return {
    accessToken: json.access_token,
    // Microsoft rotates refresh tokens; keep the old one only if no new one came back.
    refreshToken: typeof json.refresh_token === 'string' ? json.refresh_token : (previousRefresh ?? ''),
    expiresAt: now + Number(json.expires_in ?? 3600) * 1000,
  };
};

/**
 * Starts the device-code flow, shows the code through `onPrompt` and polls until the user signs in.
 * `sleep` and `now` are injectable for tests.
 */
export async function deviceCodeLogin(
  clientId: string,
  tenant: string,
  onPrompt: (p: DeviceCodePrompt) => void,
  f: Fetch = fetch,
  sleep: (ms: number) => Promise<void> = (ms) => new Promise((r) => setTimeout(r, ms)),
  now: () => number = Date.now,
): Promise<MsTokens> {
  const start = await post(`${AUTHORITY}/${tenant}/oauth2/v2.0/devicecode`, { client_id: clientId, scope: MS_SCOPE }, f);
  if (typeof start.device_code !== 'string') {
    throw new Error(`Microsoft device login could not start: ${String(start.error_description ?? start.error)}`);
  }
  onPrompt({
    userCode: String(start.user_code),
    verificationUri: String(start.verification_uri),
    message: String(start.message ?? ''),
  });
  let interval = Number(start.interval ?? 5) * 1000;
  const deadline = now() + Number(start.expires_in ?? 900) * 1000;
  while (now() < deadline) {
    await sleep(interval);
    const json = await post(
      `${AUTHORITY}/${tenant}/oauth2/v2.0/token`,
      { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', client_id: clientId, device_code: start.device_code },
      f,
    );
    if (json.error === 'authorization_pending') continue;
    if (json.error === 'slow_down') {
      interval += 5000;
      continue;
    }
    return toTokens(json, now());
  }
  throw new Error('Microsoft login timed out: the code was not used in time.');
}

export async function refreshTokens(
  clientId: string,
  tenant: string,
  refreshToken: string,
  f: Fetch = fetch,
  now: () => number = Date.now,
): Promise<MsTokens> {
  const json = await post(
    `${AUTHORITY}/${tenant}/oauth2/v2.0/token`,
    { grant_type: 'refresh_token', client_id: clientId, refresh_token: refreshToken, scope: MS_SCOPE },
    f,
  );
  return toTokens(json, now(), refreshToken);
}

/** In-memory access-token cache per account; persists rotated refresh tokens through `store`. */
export class MsTokenCache {
  private cache = new Map<string, MsTokens>();
  constructor(
    private load: (id: string) => string,
    private store: (id: string, refreshToken: string) => void,
    private f: Fetch = fetch,
    private now: () => number = Date.now,
  ) {}

  async accessToken(id: string, email: string, clientId: string): Promise<string> {
    const hit = this.cache.get(id);
    if (hit && hit.expiresAt - REFRESH_MARGIN_MS > this.now()) return hit.accessToken;
    const previous = hit?.refreshToken ?? this.load(id);
    const fresh = await refreshTokens(clientId, tenantFor(email), previous, this.f, this.now);
    if (fresh.refreshToken && fresh.refreshToken !== previous) this.store(id, fresh.refreshToken);
    this.cache.set(id, fresh);
    return fresh.accessToken;
  }
}
