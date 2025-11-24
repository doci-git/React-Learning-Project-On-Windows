const admin = require("firebase-admin");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type,Authorization,X-Device-Id",
  "Access-Control-Allow-Methods": "GET,OPTIONS",
};

function json(statusCode, body) {
  return {
    statusCode,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
    body: JSON.stringify(body),
  };
}

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

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders };
  }
  if (event.httpMethod !== "GET") {
    return json(405, { error: "Method not allowed" });
  }

  const token =
    event.queryStringParameters?.token ||
    event.queryStringParameters?.lid ||
    null;
  if (!token) return json(400, { error: "Missing token" });

  const deviceId =
    event.headers["x-device-id"] || event.headers["X-Device-Id"] || null;
  const clientIp = getClientIp(event);

  try {
    const app = initFirebase();
    const db = app.database();
    const ref = db.ref(`secure_links/${token}`);
    const snap = await ref.once("value");
    if (!snap.exists()) return json(404, { error: "Link not found" });

    const link = snap.val();
    const now = Date.now();
    const active =
      link.status === "active" &&
      (link.expiration || 0) > now &&
      (!link.maxUsage || (link.usedCount || 0) < link.maxUsage);
    if (!active) return json(403, { error: "Link expired or revoked" });

    if (link.deviceId && deviceId && link.deviceId !== deviceId) {
      return json(403, { error: "Device mismatch" });
    }
    if (!link.deviceId && deviceId) {
      await ref.update({ deviceId });
    }
    if (link.ip && clientIp && link.ip !== clientIp) {
      return json(403, { error: "IP mismatch" });
    }
    if (!link.ip && clientIp) {
      await ref.update({ ip: clientIp });
    }

    return json(200, {
      ok: true,
      customCode: link.customCode || null,
      expiration: link.expiration || null,
    });
  } catch (error) {
    console.error("validate-link error", error);
    return json(500, { error: "Internal error", message: error.message });
  }
};
