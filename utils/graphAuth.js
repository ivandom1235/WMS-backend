// backend/utils/graphAuth.js

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { ConfidentialClientApplication } = require("@azure/msal-node");

const TENANT_ID = String(process.env.MS_TENANT_ID || "").trim();
const CLIENT_ID = String(process.env.MS_CLIENT_ID || "").trim();
const RAW_SECRET = String(process.env.MS_CLIENT_SECRET || "");
const CLIENT_SECRET = RAW_SECRET.replace(/^"+|"+$/g, "").replace(/\s+/g, "").trim();

const REDIRECT_URI = String(process.env.MS_REDIRECT_URI || "").trim();
const SENDER_EMAIL = String(process.env.OPERATIONS_EMAIL || "").trim();

// Delegated scopes
const SCOPES = ["User.Read", "Mail.Send", "offline_access"];

// Token cache file (simple approach; best practice is DB/KeyVault)
const CACHE_DIR = path.join(__dirname, "..", "data");
const CACHE_FILE = path.join(CACHE_DIR, "msal_token_cache.enc");

// Encrypt cache at rest (basic local encryption)
const ENC_KEY_RAW = String(process.env.TOKEN_ENCRYPTION_KEY || "").trim();
const ENC_KEY = crypto.createHash("sha256").update(ENC_KEY_RAW).digest(); // 32 bytes
const IV_LEN = 12; // GCM standard

function ensureCacheDir() {
  if (!fs.existsSync(CACHE_DIR)) fs.mkdirSync(CACHE_DIR, { recursive: true });
}

function encrypt(plainText) {
  const iv = crypto.randomBytes(IV_LEN);
  const cipher = crypto.createCipheriv("aes-256-gcm", ENC_KEY, iv);
  const enc = Buffer.concat([cipher.update(plainText, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, enc]).toString("base64");
}

function decrypt(b64) {
  const buf = Buffer.from(b64, "base64");
  const iv = buf.subarray(0, IV_LEN);
  const tag = buf.subarray(IV_LEN, IV_LEN + 16);
  const enc = buf.subarray(IV_LEN + 16);
  const decipher = crypto.createDecipheriv("aes-256-gcm", ENC_KEY, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(enc), decipher.final()]);
  return dec.toString("utf8");
}

function loadCache() {
  try {
    if (!fs.existsSync(CACHE_FILE)) return null;
    const enc = fs.readFileSync(CACHE_FILE, "utf8");
    const json = decrypt(enc);
    return json;
  } catch (e) {
    console.error("❌ Failed to load token cache:", e?.message || e);
    return null;
  }
}

function saveCache(cacheJson) {
  try {
    ensureCacheDir();
    const enc = encrypt(cacheJson);
    fs.writeFileSync(CACHE_FILE, enc, "utf8");
    console.log("✅ Token cache saved:", { file: CACHE_FILE, size: enc.length });
  } catch (e) {
    console.error("❌ Failed to save token cache:", e?.message || e);
  }
}

function buildMsalClient() {
  if (!TENANT_ID || !CLIENT_ID || !CLIENT_SECRET || !REDIRECT_URI) {
    console.error("❌ Missing MSAL env vars:", {
      TENANT_ID: Boolean(TENANT_ID),
      CLIENT_ID: Boolean(CLIENT_ID),
      CLIENT_SECRET: CLIENT_SECRET ? "(present)" : "(missing)",
      REDIRECT_URI: Boolean(REDIRECT_URI),
    });
  }

  const msalConfig = {
    auth: {
      clientId: CLIENT_ID,
      authority: `https://login.microsoftonline.com/${TENANT_ID}`,
      clientSecret: CLIENT_SECRET,
    },
  };

  const cca = new ConfidentialClientApplication(msalConfig);

  const existing = loadCache();
  if (existing) {
    cca.getTokenCache().deserialize(existing);
    console.log("✅ MSAL cache loaded");
  } else {
    console.log("ℹ️ No MSAL cache found yet (first login required)");
  }

  return cca;
}

const cca = buildMsalClient();

/**
 * Create auth URL for login (user will open this in browser)
 */
async function getAuthUrl(req) {
  const stateObj = {
    ts: Date.now(),
    // You can add returnTo etc. if needed
  };
  const state = Buffer.from(JSON.stringify(stateObj)).toString("base64url");

  const authUrl = await cca.getAuthCodeUrl({
    scopes: SCOPES,
    redirectUri: REDIRECT_URI,
    prompt: "select_account",
    state,
  });

  console.log("🔗 Auth URL generated:", { redirectUri: REDIRECT_URI, scopes: SCOPES });
  return authUrl;
}

/**
 * Handle callback: exchange code -> tokens, store in cache
 */
async function handleAuthCallback(code) {
  console.log("🔁 Exchanging auth code for tokens...");

  const tokenResponse = await cca.acquireTokenByCode({
    code,
    scopes: SCOPES,
    redirectUri: REDIRECT_URI,
  });

  if (!tokenResponse || !tokenResponse.accessToken) {
    throw new Error("Token response missing access token");
  }

  // Persist cache
  const cacheJson = cca.getTokenCache().serialize();
  saveCache(cacheJson);

  console.log("✅ Login complete. Token acquired:", {
    account: tokenResponse.account?.username,
    expiresOn: tokenResponse.expiresOn,
    scopes: tokenResponse.scopes,
  });

  return tokenResponse;
}

/**
 * Get an access token silently (no user interaction)
 * If this fails, user must login again.
 */
async function getAccessTokenSilent() {
  const cache = cca.getTokenCache();

  const accounts = await cache.getAllAccounts();
  const account = accounts?.[0];

  console.log("🔎 Silent token request:", {
    accountsFound: accounts.length,
    usingAccount: account?.username,
    sender: SENDER_EMAIL,
  });

  if (!account) {
    throw new Error("No cached account. User must login at /auth/login first.");
  }

  try {
    const result = await cca.acquireTokenSilent({
      account,
      scopes: SCOPES,
    });

    if (!result?.accessToken) throw new Error("Silent token missing accessToken");

    // Save refreshed cache occasionally
    saveCache(cache.serialize());

    console.log("✅ Silent token OK:", {
      account: account.username,
      expiresOn: result.expiresOn,
      tokenPreview: `${result.accessToken.slice(0, 12)}...${result.accessToken.slice(-8)}`,
    });

    return result.accessToken;
  } catch (err) {
    console.error("❌ Silent token failed:", err?.message || err);
    throw new Error(
      "Silent token failed. User must re-login at /auth/login (refresh token expired/blocked)."
    );
  }
}

module.exports = {
  getAuthUrl,
  handleAuthCallback,
  getAccessTokenSilent,
  SENDER_EMAIL,
};
