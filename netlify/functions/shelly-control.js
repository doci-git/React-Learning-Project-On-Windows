const fetch = require("node-fetch");
const admin = require("firebase-admin");

const SHELLY_API_URL =
  process.env.SHELLY_API_URL ||
  "https://shelly-73-eu.shelly.cloud/v2/devices/api/set/switch";

const DEFAULT_DEVICES = [
  {
    id: "e4b063f0c38c",
    envKey: "DEVICE1_KEY",
    channel: 0,
    fallback:
      "MWI2MDc4dWlk4908A71DA809FCEC05C5D1F360943FBFC6A7934EC0FD9E3CFEAF03F8F5A6A4A0C60665B97A1AA2E2",
  },
  {
    id: "34945478d595",
    envKey: "DEVICE2_KEY",
    channel: 0,
    fallback:
      "MWI2MDc4dWlk4908A71DA809FCEC05C5D1F360943FBFC6A7934EC0FD9E3CFEAF03F8F5A6A4A0C60665B97A1AA2E2",
  },
  {
    id: "3494547ab161",
    envKey: "DEVICE3_KEY",
    channel: 0,
    fallback:
      process.env.DEVICE2_KEY ||
      "MWI2MDc4dWlk4908A71DA809FCEC05C5D1F360943FBFC6A7934EC0FD9E3CFEAF03F8F5A6A4A0C60665B97A1AA2E2",
  },
  {
    id: "placeholder_id_2",
    envKey: "DEVICE4_KEY",
    channel: 0,
    fallback: "placeholder_auth_key_2",
  },
];

const deviceMap = DEFAULT_DEVICES.reduce((acc, device) => {
  const authKey = process.env[device.envKey] || device.fallback;
  acc[device.id] = {
    id: device.id,
    authKey,
    channel: device.channel,
  };
  return acc;
}, {});

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Device-Id,X-Link-Token",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
};

function initFirebase() {
  if (admin.apps.length) return admin.app();
  const {
    FIREBASE_PROJECT_ID,
    FIREBASE_CLIENT_EMAIL,
    FIREBASE_PRIVATE_KEY,
    FIREBASE_DATABASE_URL,
  } = process.env;
  if (!FIREBASE_PROJECT_ID || !FIREBASE_CLIENT_EMAIL || !FIREBASE_PRIVATE_KEY) {
    throw new Error("Missing Firebase admin credentials in env");
  }
  return admin.initializeApp({
    credential: admin.credential.cert({
      projectId: FIREBASE_PROJECT_ID,
      clientEmail: FIREBASE_CLIENT_EMAIL,
      privateKey: FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    }),
    databaseURL: FIREBASE_DATABASE_URL,
  });
}

function getClientIp(event) {
  const xf =
    event.headers["x-forwarded-for"] || event.headers["X-Forwarded-For"];
  if (xf) {
    const ip = xf.split(",")[0].trim();
    if (ip) return ip;
  }
  const xri = event.headers["x-real-ip"] || event.headers["X-Real-IP"];
  if (xri) return xri;
  return event.requestContext?.identity?.sourceIp || null;
}

async function validateLinkToken(token, deviceId, clientIp) {
  if (!token) return { allowed: true };
  const app = initFirebase();
  const db = app.database();
  const ref = db.ref(`secure_links/${token}`);
  const snap = await ref.once("value");
  if (!snap.exists()) return { allowed: false, reason: "Link not found" };
  const link = snap.val();
  const now = Date.now();
  const active =
    link.status === "active" &&
    (link.expiration || 0) > now &&
    (!link.maxUsage || (link.usedCount || 0) < link.maxUsage);
  if (!active) return { allowed: false, reason: "Link expired or revoked" };

  if (link.deviceId && deviceId && link.deviceId !== deviceId) {
    return { allowed: false, reason: "Device mismatch" };
  }
  if (!deviceId) {
    return { allowed: false, reason: "Missing device id" };
  }
  if (!link.deviceId && deviceId) {
    await ref.update({ deviceId });
  }
  if (link.ip && clientIp && link.ip !== clientIp) {
    return { allowed: false, reason: "IP mismatch" };
  }
  if (!link.ip && clientIp) {
    await ref.update({ ip: clientIp });
  }
  return { allowed: true, link, ref, deviceId, clientIp };
}

async function incrementUsage(ref, link) {
  if (!ref) return;
  await ref.child("usedCount").transaction((v) => (v || 0) + 1);
  if (link && link.maxUsage) {
    const next = (link.usedCount || 0) + 1;
    if (next >= link.maxUsage) {
      await ref.update({ status: "used" });
    }
  }
}

function buildShellyPayload(device, command, payloadOverrides = {}) {
  const turn =
    command === "off" ? "off" : command === "toggle" ? "toggle" : "on";
  let onValue = true;
  if (command === "off") onValue = false;
  if (command === "toggle") onValue = true;

  return {
    id: device.id,
    auth_key: device.authKey,
    channel: device.channel ?? 0,
    on: onValue,
    turn,
    ...payloadOverrides,
    id: device.id,
    auth_key: device.authKey,
  };
}

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return {
      statusCode: 204,
      headers: corsHeaders,
      body: "",
    };
  }

  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ success: false, message: "Method not allowed" }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (error) {
    return {
      statusCode: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({ success: false, message: "Invalid JSON body" }),
    };
  }

  const linkToken =
    body.linkToken ||
    event.headers["x-link-token"] ||
    event.headers["authorization"];
  const callerDeviceId =
    body.clientDeviceId ||
    event.headers["x-device-id"] ||
    event.headers["x-deviceid"];
  const clientIp = getClientIp(event);

  let tokenContext = { allowed: true };
  if (linkToken) {
    try {
      tokenContext = await validateLinkToken(
        linkToken.replace(/^Bearer\s+/i, ""),
        callerDeviceId,
        clientIp
      );
    } catch (err) {
      console.error("Link validation error:", err);
      tokenContext = { allowed: false, reason: "Token validation failed" };
    }
    if (!tokenContext.allowed) {
      return {
        statusCode: 403,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({
          success: false,
          message: tokenContext.reason || "Unauthorized",
        }),
      };
    }
  }

  const { deviceId, command = "open", payload = {} } = body;
  if (!deviceId) {
    return {
      statusCode: 400,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({
        success: false,
        message: "Missing deviceId",
      }),
    };
  }

  const device = deviceMap[deviceId];
  if (!device || !device.authKey) {
    return {
      statusCode: 404,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({
        success: false,
        message: "Unknown device or missing auth key",
      }),
    };
  }

  const shellyPayload = buildShellyPayload(device, command, payload);

  try {
    const response = await fetch(SHELLY_API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(shellyPayload),
    });

    const text = await response.text();
    let data = text;
    try {
      data = text ? JSON.parse(text) : {};
    } catch (error) {
      // leave data as raw text when Shelly returns non-JSON payloads
    }

    if (!response.ok) {
      return {
        statusCode: response.status,
        headers: { ...corsHeaders, "Content-Type": "application/json" },
        body: JSON.stringify({
          success: false,
          status: response.status,
          message: "Shelly API returned an error",
          data,
        }),
      };
    }

    if (tokenContext.link && tokenContext.ref) {
      try {
        await incrementUsage(tokenContext.ref, tokenContext.link);
      } catch (err) {
        console.warn("Failed to increment link usage", err);
      }
    }

    return {
      statusCode: 200,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({
        success: true,
        status: response.status,
        data,
      }),
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers: { ...corsHeaders, "Content-Type": "application/json" },
      body: JSON.stringify({
        success: false,
        message: "Failed to reach Shelly API",
        error: error.message,
      }),
    };
  }
};
