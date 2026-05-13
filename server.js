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

    logDebug(reqId, "Granular scopes inspected", {
      granularScopeCount: granularScopes.length,
      pageCountFromGranularScopes: pageIds.length,
    });

    if (pageIds.length === 0) {
      return res.status(404).json({
        ok: false,
        requestId: reqId,
        error: "No Page IDs found in granular scopes",
        reasons: [
          "Token is valid, but granular_scopes does not include page target_ids",
          "The app may not have been granted pages_show_list on this exact token",
          "The user may not have page-level access in the connected Business/Page",
          "The token may belong to a different app, business, or role context",
        ],
        scopes,
        missingScopes,
        granularScopes,
      });
    }

    // STEP 2: Resolve each Page directly by ID from the token's granular scopes.
    const pageDetails = await Promise.all(
      pageIds.map(async (pageId) => {
        try {
          const pageInfoResponse = await axios.get(`${GRAPH_BASE}/${pageId}`, {
            params: {
              fields: "id,name,instagram_business_account",
              access_token: accessToken,
            },
          });

          const pageInfo = pageInfoResponse.data || {};
          return {
            id: pageId,
            name: pageInfo.name || null,
            hasInstagramBusinessAccount: Boolean(pageInfo.instagram_business_account?.id),
            instagramBusinessAccountId: pageInfo.instagram_business_account?.id || null,
            status: "ok",
          };
        } catch (pageError) {
          const pageErr = buildGraphError(pageError);
          logDebug(reqId, `Failed to fetch page ${pageId}`, pageErr.details);

          return {
            id: pageId,
            name: null,
            hasInstagramBusinessAccount: false,
            instagramBusinessAccountId: null,
            status: "error",
            error: pageErr.details,
          };
        }
      })
    );

    const pagesWithIg = pageDetails.filter((p) => p.hasInstagramBusinessAccount);

    return res.json({
      ok: true,
      requestId: reqId,
      tokenDebug: {
        isValid: Boolean(debugData.is_valid),
        appId: debugData.app_id,
        userId: debugData.user_id,
        expiresAt: debugData.expires_at,
        scopes,
        missingScopes,
        granularScopes,
      },
      pagesCount: pageDetails.length,
      pagesWithInstagramCount: pagesWithIg.length,
      pages: pageDetails,
      troubleshooting: pagesWithIg.length
        ? []
        : [
            "Pages exist but none has instagram_business_account linked",
            "Link your Instagram Professional account to one of these Pages",
            "Ensure your app has access to that Page and re-authorize /login",
          ],
    });
  } catch (error) {
    const graphErr = buildGraphError(error);
    logDebug(reqId, "Failed in /instagram-data", graphErr.details);
    return res.status(graphErr.status).json({
      ok: false,
      requestId: reqId,
      error: "Failed to fetch Instagram data",
      details: graphErr.details,
    });
  }
});

app.get("/debug-token", async (req, res) => {
  const reqId = makeRequestId();
  const accessToken = getUserToken(req);

  if (!accessToken) {
    return res.status(400).json({
      ok: false,
      requestId: reqId,
      error: "No access token available",
      hint: "Call /auth/callback first, set APP_ACCESS_TOKEN, or pass ?access_token=...",
    });
  }

  if (!config.appId || !config.appSecret) {
    return res.status(500).json({
      ok: false,
      requestId: reqId,
      error: "APP_ID or APP_SECRET missing in environment",
    });
  }

  try {
    logDebug(reqId, "Inspecting token with /debug_token", {
      token: maskToken(accessToken),
    });

    const debugData = await getTokenDebugInfo(accessToken);
    const scopes = extractScopes(debugData);
    const missingScopes = findMissingScopes(scopes);

    const meResponse = await axios.get(`${GRAPH_BASE}/me`, {
      params: {
        fields: "id,name",
        access_token: accessToken,
      },
    });

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
