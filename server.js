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
  "instagram_basic",
  "instagram_manage_messages",
  "instagram_manage_comments",
];
const IG_ACCOUNT_ID = "17841480751343729"; // Hardcoded specific IG Business Account ID

const config = {
  appId: process.env.APP_ID || "",
  appSecret: process.env.APP_SECRET || "",
  redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
  webhookVerifyToken: normalizeAccessToken(process.env.WEBHOOK_VERIFY_TOKEN || "my_verify_token"),
  port: Number(process.env.PORT || 3000),
  nodeEnv: process.env.NODE_ENV || "production",
};

// ===============================
// GLOBAL STATE
// ===============================
// In-memory token store tracking both the token and its origin.
let savedAccessToken = normalizeAccessToken(process.env.APP_ACCESS_TOKEN);
let tokenSource = savedAccessToken ? "Environment Variable (APP_ACCESS_TOKEN)" : "None";

// Simple in-memory dedupe set for recent event ids (keeps ids for 5 minutes).
const recentEvents = new Set();

// ===============================
// HELPER FUNCTIONS
// ===============================
function normalizeAccessToken(value) {
  if (typeof value !== "string") return "";
  return value.replace(/\s+/g, "").trim();
}

function makeRequestId() {
  return crypto.randomBytes(6).toString("hex");
}

function maskToken(token) {
  if (!token) return "<empty>";
  if (token.length <= 12) return `${token.slice(0, 2)}***${token.slice(-2)}`;
  return `${token.slice(0, 6)}...${token.slice(-6)}`;
}

function getTimestamp() {
  return new Date().toISOString();
}

function logDebug(reqId, message, meta) {
  if (meta) {
    console.log(`[${getTimestamp()}][${reqId}] ${message}`, meta);
  } else {
    console.log(`[${getTimestamp()}][${reqId}] ${message}`);
  }
}

function getUserToken(req) {
  const fromQuery = normalizeAccessToken(req.query.access_token);
  if (fromQuery) return fromQuery;
  if (savedAccessToken) return savedAccessToken;
  return normalizeAccessToken(process.env.APP_ACCESS_TOKEN);
}

function buildLoginUrl() {
  const params = new URLSearchParams({
    client_id: config.appId,
    redirect_uri: config.redirectUri,
    scope: REQUIRED_SCOPES.join(","),
    response_type: "code",
  });
  return `https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth?${params.toString()}`;
}

async function getTokenDebugInfo(userToken) {
  const appAccessToken = `${config.appId}|${config.appSecret}`;
  const response = await axios.get(`${GRAPH_BASE}/debug_token`, {
    params: {
      input_token: userToken,
      access_token: appAccessToken,
    },
  });
  return response.data?.data || {};
}

function extractScopes(debugData) {
  return Array.isArray(debugData.scopes) ? debugData.scopes : [];
}

function findMissingScopes(scopes) {
  const scopeSet = new Set(scopes);
  return REQUIRED_SCOPES.filter((scope) => !scopeSet.has(scope));
}

function buildGraphError(error) {
  return {
    status: error.response?.status || 500,
    details: error.response?.data || { message: error.message || "Unknown error" },
  };
}

function parseWebhookVerification(req) {
  return {
    mode: typeof req.query["hub.mode"] === "string" ? req.query["hub.mode"] : "",
    token: normalizeAccessToken(typeof req.query["hub.verify_token"] === "string" ? req.query["hub.verify_token"] : ""),
    challenge: typeof req.query["hub.challenge"] === "string" ? req.query["hub.challenge"] : "",
  };
}

function getWebhookSignatureHeaders(req) {
  return {
    sha256: typeof req.get("x-hub-signature-256") === "string" ? req.get("x-hub-signature-256") : "",
    legacy: typeof req.get("x-hub-signature") === "string" ? req.get("x-hub-signature") : "",
  };
}

function isDuplicateEvent(id) {
  if (recentEvents.has(id)) return true;
  recentEvents.add(id);
  setTimeout(() => recentEvents.delete(id), 1000 * 60 * 5); // Auto-expire after 5 minutes
  return false;
}

/**
 * sendInstagramDM
 * - Sends a DM via the Graph API to a specific user.
 * - Requires a valid Page Access Token linked to the IG account.
 */
async function sendInstagramDM(recipientIgUserId, messageText) {
  const token = savedAccessToken || normalizeAccessToken(process.env.APP_ACCESS_TOKEN);
  if (!token) throw new Error("No access token available for sending DMs");

  const body = {
    recipient: { user_id: recipientIgUserId },
    message: { text: messageText },
  };

  const url = `${GRAPH_BASE}/${recipientIgUserId}/messages`;
  const response = await axios.post(url, body, { params: { access_token: token } });
  return response.data;
}

// ===============================
// ROUTES: CORE & OAUTH
// ===============================

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "Instagram Automation Backend",
    graphVersion: GRAPH_VERSION,
    routes: ["/login", "/auth/callback", "/instagram-data", "/webhook", "/subscribe-app", "/check-subscription", "/token-test", "/ig-account", "/show-token"],
  });
});

/**
 * GET /login
 * OAuth Flow Step 1: Redirects the user to Facebook's OAuth dialog to grant permissions.
 */
app.get("/login", (req, res) => {
  const reqId = makeRequestId();
  if (!config.appId) return res.status(500).json({ ok: false, requestId: reqId, error: "APP_ID missing in environment" });

  const url = buildLoginUrl();
  logDebug(reqId, "Redirecting to Meta OAuth", { redirectUri: config.redirectUri });
  return res.redirect(url);
});

/**
 * GET /auth/callback
 * OAuth Flow Step 2: Meta redirects back here with a short-lived `code`.
 * We exchange this `code` for a real Access Token and store it in memory.
 * 
 */
app.get("/show-full-token", (req, res) => {
  res.json({
    token: savedAccessToken
  });
});
app.get("/auth/callback", async (req, res) => {
  const reqId = makeRequestId();
  const code = req.query.code;
  const oauthError = req.query.error || req.query.error_reason;

  if (oauthError) {
    return res.status(400).json({
      ok: false, requestId: reqId, error: "OAuth callback error",
      details: { error: req.query.error, reason: req.query.error_reason, description: req.query.error_description },
    });
  }
  if (!code) return res.status(400).json({ ok: false, requestId: reqId, error: "Missing authorization code" });
  if (!config.appId || !config.appSecret || !config.redirectUri) return res.status(500).json({ ok: false, requestId: reqId, error: "Missing configuration variables" });

  try {
    logDebug(reqId, "Exchanging OAuth code for user token");
    const tokenResponse = await axios.get(`${GRAPH_BASE}/oauth/access_token`, {
      params: { client_id: config.appId, client_secret: config.appSecret, redirect_uri: config.redirectUri, code },
    });

    const accessToken = normalizeAccessToken(tokenResponse.data?.access_token);
    if (!accessToken) return res.status(500).json({ ok: false, requestId: reqId, error: "Token exchange returned an empty token" });

    // Persist latest token and update tracking source
    savedAccessToken = accessToken;
    tokenSource = "OAuth Login Flow";
    
    logDebug(reqId, "Received and saved access token", { token: maskToken(accessToken), source: tokenSource });

    let debugData = {};
    let scopes = [];
    let missingScopes = [];

    try {
      debugData = await getTokenDebugInfo(accessToken);
      scopes = extractScopes(debugData);
      missingScopes = findMissingScopes(scopes);
    } catch (debugErr) {
      logDebug(reqId, "Failed to inspect token", buildGraphError(debugErr).details);
    }

    return res.json({
      ok: true, requestId: reqId, message: "Instagram connected successfully",
      token: { masked: maskToken(accessToken), source: tokenSource },
      scopes, missingScopes,
    });
  } catch (error) {
    const graphErr = buildGraphError(error);
    logDebug(reqId, "OAuth callback failed", graphErr.details);
    return res.status(graphErr.status).json({ ok: false, requestId: reqId, error: "OAuth failed", details: graphErr.details });
  }
});

// ===============================
// ROUTES: DIAGNOSTICS & SUBSCRIPTIONS
// ===============================

/**
 * GET /token-test
 * Tests the validity of the current token by querying the basic /me endpoint.
 */
app.get("/token-test", async (req, res) => {
  const reqId = makeRequestId();
  const token = getUserToken(req);
  if (!token) return res.status(400).json({ ok: false, error: "No token available to test." });

  try {
    const response = await axios.get(`${GRAPH_BASE}/me`, {
      params: { access_token: token, fields: "id,name,email" }
    });
    res.json({ ok: true, source: tokenSource, data: response.data });
  } catch (error) {
    res.status(error.response?.status || 500).json({ ok: false, error: "Token is invalid or expired", details: error.response?.data || error.message });
  }
});

/**
 * GET /show-token
 * Dev-only route to reveal token sources and optionally the raw token for debugging.
 */
app.get("/show-token", (req, res) => {
  const token = getUserToken(req);
  const isDev = config.nodeEnv === "development";
  
  res.json({
    ok: true,
    source: tokenSource,
    maskedToken: maskToken(token),
    fullToken: isDev ? token : "HIDDEN_IN_PRODUCTION (Set NODE_ENV=development to reveal)",
  });
});

/**
 * GET /subscribe-app
 * App Installation: Binds the app to the specific Instagram account so Meta routes webhooks to us.
 */
app.get("/subscribe-app", async (req, res) => {
  const reqId = makeRequestId();
  const token = getUserToken(req);
  if (!token) return res.status(400).json({ ok: false, error: "Missing access token" });

  try {
    logDebug(reqId, "Attempting to subscribe app to IG account webhooks", { IG_ACCOUNT_ID });
    const response = await axios.post(`${GRAPH_BASE}/${IG_ACCOUNT_ID}/subscribed_apps`, {}, {
      params: { access_token: token, subscribed_fields: "comments,messages,mentions" }
    });
    res.json({ ok: true, message: "Subscription command sent", response: response.data });
  } catch (error) {
    const graphErr = buildGraphError(error);
    logDebug(reqId, "Failed to subscribe app", graphErr.details);
    res.status(graphErr.status).json(graphErr.details);
  }
});

/**
 * GET /check-subscription
 * Verifies if the app is currently subscribed to receive webhooks for the IG account.
 */
app.get("/check-subscription", async (req, res) => {
  const reqId = makeRequestId();
  const token = getUserToken(req);
  if (!token) return res.status(400).json({ ok: false, error: "Missing access token" });

  try {
    const response = await axios.get(`${GRAPH_BASE}/${IG_ACCOUNT_ID}/subscribed_apps`, {
      params: { access_token: token }
    });
    logDebug(reqId, "Subscription status checked", response.data);
    res.json({ ok: true, data: response.data });
  } catch (error) {
    res.status(error.response?.status || 500).json(error.response?.data || error.message);
  }
});

app.get("/ig-account", async (req, res) => {
  try {
    const response = await axios.get(`${GRAPH_BASE}/${IG_ACCOUNT_ID}`, {
      params: { fields: "id,username,followers_count,media_count", access_token: getUserToken(req) },
    });
    res.json(response.data);
  } catch (error) {
    res.status(500).json(error.response?.data || error.message);
  }
});

// ===============================
// ROUTES: WEBHOOKS
// ===============================

/**
 * GET /webhook
 * Webhook Verification: Meta pings this route once when you configure the URL in the App Dashboard.
 * It ensures you control the server by matching the WEBHOOK_VERIFY_TOKEN.
 */
app.get("/webhook", (req, res) => {
  const reqId = makeRequestId();
  const { mode, token, challenge } = parseWebhookVerification(req);

  logDebug(reqId, "Webhook verification request received", { mode: mode || null, token: maskToken(token), challengeReceived: Boolean(challenge) });

  if (mode !== "subscribe" || !challenge) return res.sendStatus(400);
  
  if (token !== config.webhookVerifyToken) {
    logDebug(reqId, "Webhook verification failed: invalid verify token");
    return res.sendStatus(403);
  }

  logDebug(reqId, "WEBHOOK VERIFIED SUCCESSFULLY");
  return res.status(200).send(challenge);
});

/**
 * POST /webhook
 * Webhook Processing: Receives live events (comments, messages) from Meta.
 */
app.post("/webhook", (req, res) => {
  const reqId = makeRequestId();
  console.log(`\n[${getTimestamp()}][${reqId}] 🔥 RAW WEBHOOK PAYLOAD HIT:`);
  console.log(JSON.stringify(req.body, null, 2));

  // 1. Acknowledge immediately to prevent Meta from retrying the delivery
  res.status(200).send("EVENT_RECEIVED");

  // 2. Process events asynchronously to free up the HTTP response
  setImmediate(async () => {
    try {
      const body = req.body && typeof req.body === "object" ? req.body : {};
      const entries = Array.isArray(body.entry) ? body.entry : [];

      for (const entry of entries) {
        const changes = Array.isArray(entry.changes) ? entry.changes : [];

        for (const change of changes) {
          const value = change?.value || {};
          const fieldName = change?.field || "unknown_field";
          
          // Defensive ID check - fallback to synthetic string if strict ID is missing
          const eventId = value.comment_id || value.id || value.message_id || `${entry.id || "entry"}:${fieldName}:${value.created_time || Date.now()}`;

          // Event deduplication check
          if (isDuplicateEvent(eventId)) {
            logDebug(reqId, `Duplicate event ignored [ID: ${eventId}]`);
            continue;
          }

          // Broad check to safely handle text bodies from both real IG and Test payloads
          const isComment = value.item === "comment" || Boolean(value.comment_id) || fieldName === "comments" || typeof value.text === "string";

          if (!isComment) {
            logDebug(reqId, `Non-comment event ignored. Field: ${fieldName}`);
            continue;
          }

          // Extract metrics safely
          const commentText = String(value.text || value.message || value.comment_text || "").trim();
          const commentTextLower = commentText.toLowerCase();
          const commenterId = value.from?.id || value.commenter_id || value.user_id || null;
          const mediaId = value.media_id || value.post_id || value.parent_id || entry.id || null;

          logDebug(reqId, "💬 Comment event parsed", {
            eventId,
            fieldName,
            commenterId,
            mediaId,
            text: commentText
          });

          // Keyword automation trigger
          if (commentTextLower.includes("price")) {
            logDebug(reqId, "🎯 Keyword 'price' detected!", { eventId, commenterId });

            if (!commenterId) {
              logDebug(reqId, "❌ Cannot send DM: commenterId missing from payload.", { eventId });
              continue;
            }

            try {
              const dmText = "Thanks for asking about the price! 😊 Let me know if you need details.";
              const dmResult = await sendInstagramDM(commenterId, dmText);
              logDebug(reqId, "✅ DM sent successfully", { eventId, messageId: dmResult.message_id });
            } catch (dmError) {
              logDebug(reqId, "❌ Failed to send DM", { eventId, error: dmError?.response?.data || dmError.message });
            }
          }
        }
      }
    } catch (error) {
      logDebug(reqId, "Webhook async handler failed", { error: error.message });
    }
  });
});

// ===============================
// SERVER STARTUP
// ===============================
app.listen(config.port, () => {
  console.log("\n=================================");
  console.log("🚀 Server running on port:", config.port);
  console.log("🔄 Environment:", config.nodeEnv);
  console.log("🔗 Redirect URI:", config.redirectUri);
  console.log("=================================");
  
  // Startup Diagnostics
  console.log("🛠️  Diagnostics:");
  console.log(`- APP_ID:               ${config.appId ? "✅ Present" : "❌ Missing"}`);
  console.log(`- APP_SECRET:           ${config.appSecret ? "✅ Present" : "❌ Missing"}`);
  console.log(`- WEBHOOK_VERIFY_TOKEN: ${config.webhookVerifyToken ? "✅ Present" : "❌ Missing"}`);
  console.log(`- APP_ACCESS_TOKEN:     ${process.env.APP_ACCESS_TOKEN ? "✅ Present (Loaded into memory)" : "⚠️ Missing (Must auth via /login)"}`);
  console.log("=================================\n");
});