const express = require("express");
const axios = require("axios");
const cors = require("cors");
const crypto = require("crypto");
require("dotenv").config();

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

const config = {
  appId: process.env.APP_ID || "",
  appSecret: process.env.APP_SECRET || "",
  redirectUri: process.env.REDIRECT_URI || "http://localhost:3000/auth/callback",
  webhookVerifyToken: normalizeAccessToken(process.env.WEBHOOK_VERIFY_TOKEN || "my_verify_token"),
  port: Number(process.env.PORT || 3000),
};

// In-memory token store. For multi-instance production, persist this externally.
let savedAccessToken = normalizeAccessToken(process.env.APP_ACCESS_TOKEN);

function normalizeAccessToken(value) {
  if (typeof value !== "string") {
    return "";
  }

  // Remove accidental spaces/newlines from copy-paste.
  return value.replace(/\s+/g, "").trim();
}

function makeRequestId() {
  return crypto.randomBytes(6).toString("hex");
}

function maskToken(token) {
  if (!token) {
    return "<empty>";
  }

  if (token.length <= 12) {
    return `${token.slice(0, 2)}***${token.slice(-2)}`;
  }

  return `${token.slice(0, 6)}...${token.slice(-6)}`;
}

function getTimestamp() {
  return new Date().toISOString();
}

function logDebug(reqId, message, meta) {
  if (meta) {
    console.log(`[${getTimestamp()}][${reqId}] ${message}`, meta);
    return;
  }
  console.log(`[${getTimestamp()}][${reqId}] ${message}`);
}

function getUserToken(req) {
  const fromQuery = normalizeAccessToken(req.query.access_token);
  if (fromQuery) {
    return fromQuery;
  }

  if (savedAccessToken) {
    return savedAccessToken;
  }

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
  const scopes = Array.isArray(debugData.scopes) ? debugData.scopes : [];
  return scopes;
}

function findMissingScopes(scopes) {
  const scopeSet = new Set(scopes);
  return REQUIRED_SCOPES.filter((scope) => !scopeSet.has(scope));
}

function extractPageIdsFromGranularScopes(granularScopes) {
  if (!Array.isArray(granularScopes)) {
    return [];
  }

  // Meta may return several granular scopes, each with its own target_ids list.
  // We collect every target_id so we can bypass /me/accounts completely.
  const pageIds = granularScopes.flatMap((scope) => {
    if (!scope || !Array.isArray(scope.target_ids)) {
      return [];
    }

    return scope.target_ids;
  });

  return [...new Set(pageIds.map(String).filter(Boolean))];
}

function getSafeArray(value) {
  return Array.isArray(value) ? value : [];
}

function buildGraphError(error) {
  return {
    status: error.response?.status || 500,
    details: error.response?.data || { message: error.message || "Unknown error" },
  };
}

function parseWebhookVerification(req) {
  // Meta sends these query params when verifying the webhook endpoint.
  const mode = typeof req.query["hub.mode"] === "string" ? req.query["hub.mode"] : "";
  const token = typeof req.query["hub.verify_token"] === "string" ? req.query["hub.verify_token"] : "";
  const challenge = typeof req.query["hub.challenge"] === "string" ? req.query["hub.challenge"] : "";

  return {
    mode,
    token: normalizeAccessToken(token),
    challenge,
  };
}

function getWebhookSignatureHeaders(req) {
  // Placeholder for future signature verification.
  return {
    sha256: typeof req.get("x-hub-signature-256") === "string" ? req.get("x-hub-signature-256") : "",
    legacy: typeof req.get("x-hub-signature") === "string" ? req.get("x-hub-signature") : "",
  };
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "Instagram Automation Backend",
    graphVersion: GRAPH_VERSION,
    routes: ["/login", "/auth/callback", "/instagram-data"],
  });
});

app.get("/login", (req, res) => {
  const reqId = makeRequestId();

  if (!config.appId) {
    return res.status(500).json({
      ok: false,
      requestId: reqId,
      error: "APP_ID missing in environment",
    });
  }

  const url = buildLoginUrl();
  logDebug(reqId, "Redirecting to Meta OAuth", { redirectUri: config.redirectUri });
  return res.redirect(url);
});

app.get("/auth/callback", async (req, res) => {
  const reqId = makeRequestId();
  const code = req.query.code;
  const oauthError = req.query.error || req.query.error_reason;

  if (oauthError) {
    return res.status(400).json({
      ok: false,
      requestId: reqId,
      error: "OAuth callback contains an error",
      details: {
        error: req.query.error,
        error_reason: req.query.error_reason,
        error_description: req.query.error_description,
      },
    });
  }

  if (!code) {
    return res.status(400).json({
      ok: false,
      requestId: reqId,
      error: "Missing authorization code",
    });
  }

  if (!config.appId || !config.appSecret || !config.redirectUri) {
    return res.status(500).json({
      ok: false,
      requestId: reqId,
      error: "Missing APP_ID, APP_SECRET, or REDIRECT_URI configuration",
    });
  }

  try {
    logDebug(reqId, "Exchanging OAuth code for user token");

    const tokenResponse = await axios.get(`${GRAPH_BASE}/oauth/access_token`, {
      params: {
        client_id: config.appId,
        client_secret: config.appSecret,
        redirect_uri: config.redirectUri,
        code,
      },
    });

    const accessToken = normalizeAccessToken(tokenResponse.data?.access_token);
    const tokenType = tokenResponse.data?.token_type || "unknown";
    const expiresIn = tokenResponse.data?.expires_in || null;

    if (!accessToken) {
      return res.status(500).json({
        ok: false,
        requestId: reqId,
        error: "Token exchange succeeded but access token was empty",
      });
    }

    savedAccessToken = accessToken;
    logDebug(reqId, "Received and saved access token", {
      token: maskToken(accessToken),
      tokenType,
      expiresIn,
    });

    let debugData = {};
    let scopes = [];
    let missingScopes = [];

    try {
      debugData = await getTokenDebugInfo(accessToken);
      scopes = extractScopes(debugData);
      missingScopes = findMissingScopes(scopes);
      logDebug(reqId, "Token scopes from /debug_token", { scopes, missingScopes });
    } catch (debugErr) {
      const graphErr = buildGraphError(debugErr);
      logDebug(reqId, "Failed to inspect token", graphErr.details);
    }

    return res.json({
      ok: true,
      requestId: reqId,
      message: "Instagram connected successfully",
      token: {
        masked: maskToken(accessToken),
        tokenType,
        expiresIn,
      },
      scopes,
      missingScopes,
      note: "Token is stored in server memory as savedAccessToken",
    });
  } catch (error) {
    const graphErr = buildGraphError(error);
    logDebug(reqId, "OAuth callback failed", graphErr.details);
    return res.status(graphErr.status).json({
      ok: false,
      requestId: reqId,
      error: "OAuth failed",
      details: graphErr.details,
    });
  }
});

app.get("/instagram-data", async (req, res) => {
  const reqId = makeRequestId();
  const accessToken = getUserToken(req);

  if (!accessToken) {
    return res.status(400).json({
      ok: false,
      requestId: reqId,
      error: "No access token available",
      hint: "Call /login -> /auth/callback first, or set APP_ACCESS_TOKEN, or pass ?access_token=...",
    });
  }

  if (!config.appId || !config.appSecret) {
    return res.status(500).json({
      ok: false,
      requestId: reqId,
      error: "APP_ID or APP_SECRET missing in environment",
    });
  }

  logDebug(reqId, "Using token for /instagram-data", {
    token: maskToken(accessToken),
  });

  try {
    // STEP 1: Validate the token and inspect granular scopes first.
    const debugData = await getTokenDebugInfo(accessToken);
    const scopes = extractScopes(debugData);
    const missingScopes = findMissingScopes(scopes);
    const granularScopes = getSafeArray(debugData.granular_scopes);
    const pageIds = extractPageIdsFromGranularScopes(granularScopes);

    if (!debugData.is_valid) {
      return res.status(401).json({
        ok: false,
        requestId: reqId,
        error: "Access token is invalid",
        debugToken: {
          appId: debugData.app_id,
          userId: debugData.user_id,
          expiresAt: debugData.expires_at,
          isValid: debugData.is_valid,
          scopes,
          missingScopes,
        },
      });
    }

    // WEBHOOK EVENTS
    // Meta sends Instagram webhook payloads here after verification succeeds.
    // This handler is defensive and never assumes req.body has a specific shape.
    app.post("/webhook", (req, res) => {
      const reqId = makeRequestId();
      // Developer convenience: print raw body to console for quick debugging
      console.log("======================================");
      console.log("WEBHOOK POST HIT");
      console.log(new Date().toISOString());
      console.log("\nBODY:");
      try {
        console.log(JSON.stringify(req.body, null, 2));
      } catch (e) {
        console.log(String(req.body));
      }
      console.log("======================================");

      // Acknowledge immediately to avoid Meta retries. Processing continues async.
      res.status(200).send("EVENT_RECEIVED");

      (async () => {
        try {
          const signatures = getWebhookSignatureHeaders(req);
          if (signatures.sha256 || signatures.legacy) {
            logDebug(reqId, "Webhook signature headers detected", {
              hasSha256: Boolean(signatures.sha256),
              hasLegacy: Boolean(signatures.legacy),
            });
          }

          const body = req.body && typeof req.body === "object" ? req.body : {};

          logDebug(reqId, "Instagram webhook event received", {
            object: body.object || null,
            entryCount: Array.isArray(body.entry) ? body.entry.length : 0,
          });

          // Process each entry -> changes array.
          const entries = Array.isArray(body.entry) ? body.entry : [];

          for (const entry of entries) {
            const changes = Array.isArray(entry.changes) ? entry.changes : [];

            for (const change of changes) {
              const value = change?.value || {};

              // Build a dedupe id for the event. Prefer comment_id if present.
              const eventId = value.comment_id || value.id || value.message_id || `${entry.id || ""}:${change.field || ""}:${value.created_time || ""}`;

              if (!eventId) {
                logDebug(reqId, "Skipping event with no identifiable id", { change });
                continue;
              }

              if (isDuplicateEvent(eventId)) {
                logDebug(reqId, "Duplicate event ignored", { eventId });
                continue;
              }

              // Detect comment events. Meta uses 'item': 'comment' and 'verb': 'add' for new comments.
              const isComment = value?.item === "comment" || Boolean(value?.comment_id) || typeof value?.text === "string";

              if (!isComment) {
                logDebug(reqId, "Non-comment event ignored", { field: change.field || null });
                continue;
              }

              // Extract comment metadata safely
              const commentText = (value.text || value.message || value.comment_text || "").toString();
              const commentTextLower = commentText.toLowerCase();
              const commenterId = value.from?.id || value.commenter_id || value.user_id || null;
              const mediaId = value.media_id || value.post_id || value.parent_id || entry?.id || null;

              logDebug(reqId, "Comment event parsed", {
                eventId,
                commenterId,
                mediaId,
                snippet: commentText.slice(0, 120),
              });

              // Keyword detection
              if (commentTextLower.includes("price")) {
                logDebug(reqId, "Keyword 'price' detected", { eventId, commenterId });

                if (!commenterId) {
                  logDebug(reqId, "Cannot send DM: commenterId missing", { eventId });
                  continue;
                }

                try {
                  // Compose DM
                  const dmText = "Thanks for the comment 😊";
                  const dmResult = await sendInstagramDM(commenterId, dmText);
                  logDebug(reqId, "DM send result", { eventId, dmResult });
                } catch (dmError) {
                  logDebug(reqId, "Failed to send DM", { eventId, error: dmError?.message || dmError });
                }
              }
            }
          }
        } catch (processingError) {
          logDebug(reqId, "Error processing webhook payload", { error: processingError?.message || processingError });
        }
      })();
    });

    // Simple in-memory dedupe set for recent event ids (keeps ids for 5 minutes).
    // For production, replace with Redis or durable store shared across instances.
    const recentEvents = new Set();
    function isDuplicateEvent(id) {
      if (recentEvents.has(id)) return true;
      recentEvents.add(id);
      // auto-expire
      setTimeout(() => recentEvents.delete(id), 1000 * 60 * 5);
      return false;
    }

    /**
     * sendInstagramDM
     * - recipientIgUserId: Instagram user id (scoped)
     * - messageText: plain text message to send
     * Uses the Graph API: POST /{ig-user-id}/messages with recipient + message
     * NOTE: Requires a Page/IG Messaging access token with messaging permission.
     */
    async function sendInstagramDM(recipientIgUserId, messageText) {
      const token = savedAccessToken || normalizeAccessToken(process.env.APP_ACCESS_TOKEN);

      if (!token) {
        throw new Error("No access token available for sending DMs");
      }

      // Build request body per Instagram Messaging API
      const body = {
        recipient: { user_id: recipientIgUserId },
        message: { text: messageText },
      };

      const url = `${GRAPH_BASE}/${recipientIgUserId}/messages`;

      const response = await axios.post(url, body, { params: { access_token: token } });
      return response.data;
    }
    logDebug(reqId, "Token /debug_token and /me responses ready", {
      isValid: debugData.is_valid,
      scopes,
      missingScopes,
    });

    return res.json({
      ok: true,
      requestId: reqId,
      token: {
        masked: maskToken(accessToken),
      },
      debugToken: debugData,
      me: meResponse.data,
      scopes,
      missingScopes,
    });
  } catch (error) {
    const graphErr = buildGraphError(error);
    logDebug(reqId, "Debug-token route failed", graphErr.details);
    return res.status(graphErr.status).json({
      ok: false,
      requestId: reqId,
      error: "Debug failed",
      details: graphErr.details,
    });
  }
});

// ===============================
// WEBHOOK CONFIG
// ===============================
// Use a dedicated verify token for Meta webhook setup.
// Store it in WEBHOOK_VERIFY_TOKEN in production.

// WEBHOOK VERIFICATION
// Meta calls this route during webhook setup with hub.mode, hub.verify_token, and hub.challenge.
app.get("/webhook", (req, res) => {
  const reqId = makeRequestId();
  const { mode, token, challenge } = parseWebhookVerification(req);

  logDebug(reqId, "Webhook verification request received", {
    mode: mode || null,
    token: maskToken(token),
    challengeReceived: Boolean(challenge),
  });

  if (mode !== "subscribe") {
    return res.sendStatus(400);
  }

  if (!challenge) {
    return res.sendStatus(400);
  }

  if (token !== config.webhookVerifyToken) {
    logDebug(reqId, "Webhook verification failed: invalid verify token");
    return res.sendStatus(403);
  }

  logDebug(reqId, "WEBHOOK VERIFIED SUCCESSFULLY");
  return res.status(200).send(challenge);
});

// WEBHOOK EVENTS
// Meta sends Instagram webhook payloads here after verification succeeds.
// This handler is defensive and never assumes req.body has a specific shape.
app.post("/webhook", (req, res) => {
  const reqId = makeRequestId();

  try {
    const signatures = getWebhookSignatureHeaders(req);
    if (signatures.sha256 || signatures.legacy) {
      logDebug(reqId, "Webhook signature headers detected", {
        hasSha256: Boolean(signatures.sha256),
        hasLegacy: Boolean(signatures.legacy),
      });
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};

    logDebug(reqId, "Instagram webhook event received", {
      object: body.object || null,
      entryCount: Array.isArray(body.entry) ? body.entry.length : 0,
    });

    console.log(`[${getTimestamp()}][${reqId}] WEBHOOK EVENT PAYLOAD`);
    console.log(JSON.stringify(body, null, 2));

    // ACK quickly so Meta does not retry the delivery.
    return res.sendStatus(200);
  } catch (error) {
    logDebug(reqId, "Webhook event handler failed", {
      error: error.message || "Unknown error",
    });

    return res.sendStatus(500);
  }
});

app.listen(config.port, () => {
  console.log(`Server running on port ${config.port}`);
  console.log(`Redirect URI: ${config.redirectUri}`);
});
