const express = require("express");
const axios = require("axios");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

// ===============================
// CONFIGURATION & SETUP
// ===============================
const app = express();
app.use(cors());
app.use(express.json());

const GRAPH_VERSION = "v25.0";
const GRAPH_BASE = `https://graph.facebook.com/${GRAPH_VERSION}`;

const REQUIRED_SCOPES = [
  "public_profile",
  "pages_show_list",
  "pages_manage_metadata",
  "instagram_basic",
  "instagram_manage_messages",
  "instagram_manage_comments",
];

// IG Business Account ID — owner of the posts we're watching
const IG_ACCOUNT_ID = "17841480751343729";

const config = {
  appId: process.env.APP_ID || "",
  appSecret: process.env.APP_SECRET || "",
  redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
  webhookVerifyToken: (process.env.WEBHOOK_VERIFY_TOKEN || "my_verify_token").trim(),
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || "production",
};

// ===============================
// GLOBAL STATE
// ===============================
// User Access Token — set via OAuth /login or APP_ACCESS_TOKEN env var
let userAccessToken = normalizeToken(process.env.APP_ACCESS_TOKEN);
let userTokenSource = userAccessToken ? "ENV:APP_ACCESS_TOKEN" : "None";

// Page Access Token — required for subscribed_apps + sending DMs
// Set this in env as PAGE_ACCESS_TOKEN after running /page-token once
let pageAccessToken = normalizeToken(process.env.PAGE_ACCESS_TOKEN);
let pageTokenSource = pageAccessToken ? "ENV:PAGE_ACCESS_TOKEN" : "None";

// Dedupe set — prevents double-processing same webhook event (auto-expires in 5min)
const recentEvents = new Set();

// ===============================
// HELPERS
// ===============================
function normalizeToken(value) {
  if (typeof value !== "string") return "";
  return value.replace(/\s+/g, "").trim();
}

function maskToken(token) {
  if (!token) return "<empty>";
  if (token.length <= 12) return `${token.slice(0, 2)}***${token.slice(-2)}`;
  return `${token.slice(0, 6)}...${token.slice(-6)}`;
}

function makeRequestId() {
  return crypto.randomBytes(5).toString("hex");
}

function ts() {
  return new Date().toISOString();
}

function log(reqId, msg, meta) {
  const prefix = `[${ts()}][${reqId}]`;
  meta ? console.log(`${prefix} ${msg}`, JSON.stringify(meta, null, 2)) : console.log(`${prefix} ${msg}`);
}

function graphError(error) {
  return {
    status: error.response?.status || 500,
    details: error.response?.data || { message: error.message || "Unknown error" },
  };
}

function isDuplicateEvent(id) {
  if (recentEvents.has(id)) return true;
  recentEvents.add(id);
  setTimeout(() => recentEvents.delete(id), 5 * 60 * 1000);
  return false;
}

// ===============================
// CORE GRAPH API FUNCTIONS
// ===============================

/**
 * Fetches all Facebook Pages the current user manages.
 * Each page has its own access_token — we need this for subscribed_apps + DMs.
 */
async function fetchUserPages(token) {
  const res = await axios.get(`${GRAPH_BASE}/me/accounts`, {
    params: { access_token: token, fields: "id,name,access_token,instagram_business_account" },
  });
  return res.data?.data || [];
}

/**
 * Subscribes the app to a specific IG account's webhook fields.
 * MUST use Page Access Token (not User token).
 */
async function subscribeAppToIG(pageToken) {
  const res = await axios.post(
    `${GRAPH_BASE}/${IG_ACCOUNT_ID}/subscribed_apps`,
    {},
    { params: { access_token: pageToken, subscribed_fields: "comments,messages,mentions" } }
  );
  return res.data;
}

/**
 * Sends a DM from the IG Business account to a recipient.
 * Endpoint: POST /{IG_ACCOUNT_ID}/messages  (NOT /{recipientId}/messages)
 * Requires: Page Access Token
 */
async function sendDM(recipientIgUserId, messageText) {
  const token = pageAccessToken || userAccessToken;
  if (!token) throw new Error("No token available for sending DM");

  const res = await axios.post(
    `${GRAPH_BASE}/${IG_ACCOUNT_ID}/messages`,
    {
      recipient: { id: recipientIgUserId },  // NOTE: "id" not "user_id"
      message: { text: messageText },
    },
    { params: { access_token: token } }
  );
  return res.data;
}

/**
 * Debugs a token using the App Access Token.
 */
async function debugToken(inputToken) {
  const appToken = `${config.appId}|${config.appSecret}`;
  const res = await axios.get(`${GRAPH_BASE}/debug_token`, {
    params: { input_token: inputToken, access_token: appToken },
  });
  return res.data?.data || {};
}

// ===============================
// ROUTES: ROOT
// ===============================

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "Instagram Automation Backend",
    version: GRAPH_VERSION,
    mode: config.nodeEnv,
    tokenStatus: {
      userToken: userAccessToken ? `set (${userTokenSource})` : "missing — visit /login",
      pageToken: pageAccessToken ? `set (${pageTokenSource})` : "missing — visit /page-token after login",
    },
    routes: {
      auth: ["/login", "/auth/callback"],
      diagnostics: ["/token-test", "/ig-account", "/page-token", "/show-token"],
      subscriptions: ["/subscribe-app", "/check-subscription"],
      testing: ["/test-dm?to=IG_USER_ID", "/test-webhook-payload"],
      webhook: ["GET /webhook (verification)", "POST /webhook (events)"],
    },
  });
});

// ===============================
// ROUTES: OAUTH
// ===============================

/**
 * Step 1: Redirect to Meta OAuth dialog.
 * Added pages_manage_metadata scope — required for subscribed_apps to work.
 */
app.get("/login", (req, res) => {
  const reqId = makeRequestId();
  if (!config.appId) {
    return res.status(500).json({ ok: false, error: "APP_ID missing" });
  }
  const params = new URLSearchParams({
    client_id: config.appId,
    redirect_uri: config.redirectUri,
    scope: REQUIRED_SCOPES.join(","),
    response_type: "code",
  });
  const url = `https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth?${params}`;
  log(reqId, `🔐 Redirecting to OAuth`, { scopes: REQUIRED_SCOPES });
  res.redirect(url);
});

/**
 * Step 2: Meta redirects here with a short-lived code.
 * Exchange it for a User Access Token, then auto-fetch page tokens.
 */
app.get("/auth/callback", async (req, res) => {
  const reqId = makeRequestId();
  const { code, error: oauthError, error_description } = req.query;

  if (oauthError) {
    log(reqId, `❌ OAuth error: ${oauthError}`, { error_description });
    return res.status(400).json({ ok: false, error: oauthError, description: error_description });
  }
  if (!code) {
    return res.status(400).json({ ok: false, error: "Missing authorization code" });
  }

  try {
    // Exchange code for user access token
    const tokenRes = await axios.get(`${GRAPH_BASE}/oauth/access_token`, {
      params: {
        client_id: config.appId,
        client_secret: config.appSecret,
        redirect_uri: config.redirectUri,
        code,
      },
    });

    const token = normalizeToken(tokenRes.data?.access_token);
    if (!token) throw new Error("Empty token in exchange response");

    userAccessToken = token;
    userTokenSource = "OAuth /auth/callback";
    log(reqId, `✅ User access token acquired`, { token: maskToken(token) });

    // Inspect token scopes
    let debugData = {};
    try {
      debugData = await debugToken(token);
    } catch (e) {
      log(reqId, `⚠️ Token debug failed (non-fatal)`, { error: e.message });
    }

    const grantedScopes = debugData.scopes || [];
    const missingScopes = REQUIRED_SCOPES.filter((s) => !grantedScopes.includes(s));

    // Try to auto-find page token
    let pages = [];
    let autoPageToken = null;
    try {
      pages = await fetchUserPages(token);
      // Find page linked to our IG account
      const matchedPage = pages.find(
        (p) => p.instagram_business_account?.id === IG_ACCOUNT_ID
      );
      if (matchedPage) {
        autoPageToken = matchedPage.access_token;
        pageAccessToken = autoPageToken;
        pageTokenSource = `Auto-detected from page: ${matchedPage.name}`;
        log(reqId, `✅ Page token auto-detected`, { page: matchedPage.name, id: matchedPage.id });
      }
    } catch (e) {
      log(reqId, `⚠️ Page auto-detection failed (non-fatal)`, { error: e.message });
    }

    return res.json({
      ok: true,
      message: "OAuth complete",
      userToken: maskToken(token),
      grantedScopes,
      missingScopes,
      pageTokenDetected: Boolean(autoPageToken),
      pages: pages.map((p) => ({ id: p.id, name: p.name, hasIgLinked: Boolean(p.instagram_business_account) })),
      nextStep: autoPageToken
        ? "✅ Page token found. Now visit /subscribe-app"
        : "⚠️ No page linked to this IG account. Visit /page-token to inspect, then link a Facebook Page.",
    });
  } catch (error) {
    const err = graphError(error);
    log(reqId, `❌ OAuth callback failed`, err.details);
    return res.status(err.status).json({ ok: false, error: "OAuth failed", details: err.details });
  }
});

// ===============================
// ROUTES: DIAGNOSTICS
// ===============================

/**
 * GET /token-test
 * Tests user access token against /me endpoint.
 */
app.get("/token-test", async (req, res) => {
  const reqId = makeRequestId();
  const token = normalizeToken(req.query.access_token) || userAccessToken;
  if (!token) return res.status(400).json({ ok: false, error: "No token. Visit /login first." });

  try {
    const [meRes, debugData] = await Promise.all([
      axios.get(`${GRAPH_BASE}/me`, { params: { access_token: token, fields: "id,name" } }),
      debugToken(token).catch(() => ({})),
    ]);

    const grantedScopes = debugData.scopes || [];
    const missingScopes = REQUIRED_SCOPES.filter((s) => !grantedScopes.includes(s));

    log(reqId, `✅ Token test passed`, { user: meRes.data });
    res.json({
      ok: true,
      source: userTokenSource,
      user: meRes.data,
      grantedScopes,
      missingScopes,
      expiresAt: debugData.expires_at ? new Date(debugData.expires_at * 1000).toISOString() : "unknown",
    });
  } catch (error) {
    const err = graphError(error);
    log(reqId, `❌ Token test failed`, err.details);
    res.status(err.status).json({ ok: false, error: "Token invalid or expired", details: err.details });
  }
});

/**
 * GET /ig-account
 * Verifies IG account is accessible and returns basic stats.
 */
app.get("/ig-account", async (req, res) => {
  const reqId = makeRequestId();
  const token = normalizeToken(req.query.access_token) || userAccessToken;
  if (!token) return res.status(400).json({ ok: false, error: "No token. Visit /login first." });

  try {
    const igRes = await axios.get(`${GRAPH_BASE}/${IG_ACCOUNT_ID}`, {
      params: { access_token: token, fields: "id,username,followers_count,media_count,profile_picture_url" },
    });
    log(reqId, `✅ IG account fetched`, igRes.data);
    res.json({ ok: true, account: igRes.data });
  } catch (error) {
    const err = graphError(error);
    log(reqId, `❌ IG account fetch failed`, err.details);
    res.status(err.status).json({ ok: false, error: "Could not fetch IG account", details: err.details });
  }
});

/**
 * GET /page-token
 * Lists all Facebook Pages the user manages, with their access tokens.
 * Use this to find the Page linked to your IG account.
 * Copy the matching page access_token → set as PAGE_ACCESS_TOKEN in Render env vars.
 */
app.get("/page-token", async (req, res) => {
  const reqId = makeRequestId();
  const token = normalizeToken(req.query.access_token) || userAccessToken;
  if (!token) return res.status(400).json({ ok: false, error: "No token. Visit /login first." });

  try {
    const pages = await fetchUserPages(token);
    log(reqId, `✅ Fetched ${pages.length} pages`);

    if (pages.length === 0) {
      return res.json({
        ok: false,
        pages: [],
        diagnosis: "No Facebook Pages found. You must create a Facebook Page and link it to your Instagram Business account.",
        howToFix: [
          "1. Go to https://www.facebook.com/pages/create",
          "2. Create a Page (any category)",
          "3. Go to your Instagram app → Settings → Account → Linked Accounts → Facebook",
          "4. Connect to this new Page",
          "5. Make sure Instagram account type is Business (not Personal)",
          "6. Re-run /login to get a fresh token",
          "7. Re-visit /page-token",
        ],
      });
    }

    const linkedPage = pages.find((p) => p.instagram_business_account?.id === IG_ACCOUNT_ID);

    if (linkedPage) {
      // Auto-save page token in memory
      pageAccessToken = linkedPage.access_token;
      pageTokenSource = `Page: ${linkedPage.name} (${linkedPage.id})`;
      log(reqId, `✅ Page linked to IG account found and saved`, { name: linkedPage.name });
    }

    res.json({
      ok: true,
      pagesFound: pages.length,
      igLinkedPage: linkedPage
        ? {
            id: linkedPage.id,
            name: linkedPage.name,
            igAccountId: linkedPage.instagram_business_account?.id,
            pageAccessToken: linkedPage.access_token,
          }
        : null,
      allPages: pages.map((p) => ({
        id: p.id,
        name: p.name,
        igLinked: Boolean(p.instagram_business_account),
        igAccountId: p.instagram_business_account?.id || null,
        pageAccessToken: p.access_token,
      })),
      nextStep: linkedPage
        ? `✅ Copy the pageAccessToken above and set it as PAGE_ACCESS_TOKEN in Render env vars, then visit /subscribe-app`
        : `⚠️ None of your pages are linked to IG account ${IG_ACCOUNT_ID}. Link a page to this IG account first.`,
    });
  } catch (error) {
    const err = graphError(error);
    log(reqId, `❌ Page fetch failed`, err.details);
    res.status(err.status).json({ ok: false, error: "Could not fetch pages", details: err.details });
  }
});

/**
 * GET /show-token
 * Shows current token state. Full tokens shown in development mode only.
 */
app.get("/show-token", (req, res) => {
  const isDev = config.nodeEnv === "development";
  res.json({
    ok: true,
    userToken: {
      source: userTokenSource,
      masked: maskToken(userAccessToken),
      full: isDev ? userAccessToken : "Set NODE_ENV=development to reveal",
    },
    pageToken: {
      source: pageTokenSource,
      masked: maskToken(pageAccessToken),
      full: isDev ? pageAccessToken : "Set NODE_ENV=development to reveal",
    },
  });
});

// ===============================
// ROUTES: SUBSCRIPTIONS
// ===============================

/**
 * GET /subscribe-app
 * Links this app to receive webhook events for the IG account.
 * REQUIRES Page Access Token — will fail with User token.
 */
app.get("/subscribe-app", async (req, res) => {
  const reqId = makeRequestId();
  const token = normalizeToken(req.query.page_token) || pageAccessToken;

  if (!token) {
    return res.status(400).json({
      ok: false,
      error: "No Page Access Token found",
      fix: "Visit /page-token first to fetch and auto-save your Page token, then retry /subscribe-app",
    });
  }

  try {
    log(reqId, `📡 Subscribing app to IG account`, { IG_ACCOUNT_ID, token: maskToken(token) });
    const result = await subscribeAppToIG(token);
    log(reqId, `✅ Subscription successful`, result);
    res.json({
      ok: true,
      message: "App subscribed to IG account webhooks",
      result,
      subscribedFields: ["comments", "messages", "mentions"],
      nextStep: "Visit /check-subscription to confirm, then post a comment from thrivex.labs to test real webhook delivery",
    });
  } catch (error) {
    const err = graphError(error);
    log(reqId, `❌ Subscribe failed`, err.details);
    res.status(err.status).json({
      ok: false,
      error: "Subscription failed",
      details: err.details,
      commonCauses: [
        "Using User token instead of Page token",
        "Page not linked to the IG account",
        "Missing pages_manage_metadata scope — re-run /login",
      ],
    });
  }
});

/**
 * GET /check-subscription
 * Checks if the app is subscribed to IG account webhooks.
 */
app.get("/check-subscription", async (req, res) => {
  const reqId = makeRequestId();
  const token = normalizeToken(req.query.page_token) || pageAccessToken || userAccessToken;
  if (!token) return res.status(400).json({ ok: false, error: "No token available" });

  try {
    const result = await axios.get(`${GRAPH_BASE}/${IG_ACCOUNT_ID}/subscribed_apps`, {
      params: { access_token: token },
    });
    log(reqId, `✅ Subscription check`, result.data);
    res.json({ ok: true, data: result.data });
  } catch (error) {
    const err = graphError(error);
    log(reqId, `❌ Check subscription failed`, err.details);
    res.status(err.status).json({ ok: false, error: "Check failed", details: err.details });
  }
});

// ===============================
// ROUTES: TESTING
// ===============================

/**
 * GET /test-dm?to=IG_USER_ID
 * Manually trigger a DM to verify DM sending works before real webhooks arrive.
 * Usage: /test-dm?to=123456789
 */
app.get("/test-dm", async (req, res) => {
  const reqId = makeRequestId();
  const recipientId = req.query.to;
  if (!recipientId) {
    return res.status(400).json({ ok: false, error: "Missing ?to=IG_USER_ID query param" });
  }

  try {
    log(reqId, `📨 Test DM triggered`, { to: recipientId });
    const result = await sendDM(recipientId, "✅ This is a test DM from your Instagram automation bot!");
    log(reqId, `✅ Test DM sent`, result);
    res.json({ ok: true, message: "DM sent successfully", result });
  } catch (error) {
    const err = graphError(error);
    log(reqId, `❌ Test DM failed`, err.details);
    res.status(err.status).json({ ok: false, error: "DM send failed", details: err.details });
  }
});

/**
 * POST /test-webhook-payload
 * Simulate a real Instagram comment webhook event locally.
 * Usage: POST /test-webhook-payload with body:
 * { "commentText": "price", "commenterId": "123456789" }
 */
app.post("/test-webhook-payload", (req, res) => {
  const reqId = makeRequestId();
  const { commentText = "price", commenterId = "TEST_USER_123" } = req.body;

  // Construct a fake but realistic IG webhook payload
  const fakePayload = {
    object: "instagram",
    entry: [
      {
        id: IG_ACCOUNT_ID,
        time: Math.floor(Date.now() / 1000),
        changes: [
          {
            field: "comments",
            value: {
              from: { id: commenterId, username: "test_user" },
              media: { id: "MEDIA_123", media_product_type: "POST" },
              id: `COMMENT_${Date.now()}`,
              text: commentText,
            },
          },
        ],
      },
    ],
  };

  log(reqId, `🧪 Injecting fake webhook payload`, fakePayload);

  // Process it through the same logic as real webhooks
  req.body = fakePayload;
  res.status(200).json({ ok: true, message: "Fake payload injected — check server logs", payload: fakePayload });

  // Trigger async processing
  setImmediate(() => processWebhookBody(fakePayload, reqId));
});

// ===============================
// WEBHOOK PROCESSING LOGIC
// ===============================

/**
 * Core webhook processor — shared by both real POST /webhook and test injection.
 */
async function processWebhookBody(body, reqId) {
  const entries = Array.isArray(body.entry) ? body.entry : [];

  for (const entry of entries) {
    const changes = Array.isArray(entry.changes) ? entry.changes : [];

    for (const change of changes) {
      const value = change?.value || {};
      const fieldName = change?.field || "unknown";

      // Build a stable event ID for deduplication
      const eventId =
        value.id ||
        value.comment_id ||
        value.message_id ||
        `${entry.id}:${fieldName}:${value.created_time || Date.now()}`;

      if (isDuplicateEvent(eventId)) {
        log(reqId, `⏭️ Duplicate event skipped`, { eventId });
        continue;
      }

      // Detect comment events broadly (handles both real + test payloads)
      const isComment =
        fieldName === "comments" ||
        value.item === "comment" ||
        Boolean(value.comment_id) ||
        typeof value.text === "string";

      if (!isComment) {
        log(reqId, `ℹ️ Non-comment field ignored`, { fieldName, eventId });
        continue;
      }

      // Extract comment data safely
      const commentText = String(value.text || value.message || value.comment_text || "").trim();
      const commenterId = value.from?.id || value.commenter_id || value.user_id || null;
      const mediaId = value.media?.id || value.media_id || value.post_id || entry.id || null;

      log(reqId, `💬 Comment event received`, {
        eventId,
        field: fieldName,
        commenterId,
        mediaId,
        text: commentText,
      });

      // ─── KEYWORD TRIGGERS ───────────────────────────────────────────
      const lower = commentText.toLowerCase();

      if (lower.includes("price")) {
        log(reqId, `🎯 Keyword "price" detected — triggering DM`, { commenterId, eventId });

        if (!commenterId) {
          log(reqId, `❌ DM skipped — commenterId missing from payload`);
          continue;
        }

        try {
          const dmResult = await sendDM(
            commenterId,
            "Hey! Thanks for your interest 😊 Here are the pricing details — [ADD YOUR PRICE INFO HERE]. Feel free to DM us for more info!"
          );
          log(reqId, `✅ DM sent`, { messageId: dmResult.message_id, to: commenterId });
        } catch (dmError) {
          log(reqId, `❌ DM failed`, {
            error: dmError?.response?.data || dmError.message,
            commenterId,
          });
        }
      }

      // Add more keyword triggers here:
      // if (lower.includes("buy")) { ... }
      // if (lower.includes("available")) { ... }
    }
  }
}

// ===============================
// ROUTES: WEBHOOK
// ===============================

/**
 * GET /webhook
 * Meta pings this once during setup to verify you own the server.
 */
app.get("/webhook", (req, res) => {
  const reqId = makeRequestId();
  const mode = req.query["hub.mode"];
  const token = normalizeToken(req.query["hub.verify_token"]);
  const challenge = req.query["hub.challenge"];

  log(reqId, `🔔 Webhook verification request`, { mode, token: maskToken(token) });

  if (mode !== "subscribe" || !challenge) {
    log(reqId, `❌ Invalid verification request`);
    return res.sendStatus(400);
  }

  if (token !== config.webhookVerifyToken) {
    log(reqId, `❌ Verify token mismatch`, {
      received: maskToken(token),
      expected: maskToken(config.webhookVerifyToken),
    });
    return res.sendStatus(403);
  }

  log(reqId, `✅ WEBHOOK VERIFIED`);
  return res.status(200).send(challenge);
});

/**
 * POST /webhook
 * Receives real-time Instagram events (comments, messages, mentions).
 */
app.post("/webhook", (req, res) => {
  const reqId = makeRequestId();

  console.log(`\n${"=".repeat(60)}`);
  console.log(`[${ts()}][${reqId}] 🔥 INCOMING WEBHOOK`);
  console.log(JSON.stringify(req.body, null, 2));
  console.log("=".repeat(60));

  // Respond immediately — Meta requires < 5s response or it will retry
  res.status(200).send("EVENT_RECEIVED");

  // Process asynchronously
  setImmediate(() => processWebhookBody(req.body, reqId));
});

// ===============================
// SERVER STARTUP
// ===============================
app.listen(config.port, () => {
  console.log("\n" + "=".repeat(50));
  console.log(`🚀 Server started — port ${config.port}`);
  console.log(`🌍 Mode: ${config.nodeEnv}`);
  console.log(`🔗 Redirect URI: ${config.redirectUri}`);
  console.log("=".repeat(50));
  console.log("🛠️  Config check:");
  console.log(`  APP_ID               ${config.appId ? "✅" : "❌ MISSING"}`);
  console.log(`  APP_SECRET           ${config.appSecret ? "✅" : "❌ MISSING"}`);
  console.log(`  WEBHOOK_VERIFY_TOKEN ${config.webhookVerifyToken ? "✅" : "❌ MISSING"}`);
  console.log(`  APP_ACCESS_TOKEN     ${process.env.APP_ACCESS_TOKEN ? "✅" : "⚠️  missing — visit /login"}`);
  console.log(`  PAGE_ACCESS_TOKEN    ${process.env.PAGE_ACCESS_TOKEN ? "✅" : "⚠️  missing — visit /page-token after login"}`);
  console.log("=".repeat(50));
  console.log("📋 Startup checklist:");
  console.log("  1. Visit /login → complete OAuth");
  console.log("  2. Visit /page-token → find + save page token");
  console.log("  3. Visit /subscribe-app → link app to IG account");
  console.log("  4. Visit /check-subscription → confirm active");
  console.log("  5. Post a comment from thrivex.labs → watch logs");
  console.log("=".repeat(50) + "\n");
});