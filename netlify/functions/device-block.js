const admin = require("firebase-admin");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
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

exports.handler = async (event) => {
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 204, headers: corsHeaders };
  }

  const app = initFirebase();
  const db = app.database();
  const ref = db.ref("blocked_devices");

  if (event.httpMethod === "GET") {
    const deviceId =
      event.queryStringParameters?.deviceId ||
      event.queryStringParameters?.id ||
      null;
    if (!deviceId) return json(400, { error: "Missing deviceId" });
    const snap = await ref.child(deviceId).once("value");
    if (!snap.exists()) return json(200, { blocked: false });
    const val = snap.val() || {};
    return json(200, { blocked: !!val.blocked, reason: val.reason || null });
  }

  if (event.httpMethod === "POST") {
    let body = {};
    try {
      body = JSON.parse(event.body || "{}");
    } catch (e) {
      return json(400, { error: "Invalid JSON body" });
    }
    const { deviceId, reason = "blocked" } = body;
    if (!deviceId) return json(400, { error: "Missing deviceId" });
    await ref.child(deviceId).set({
      blocked: true,
      reason,
      ts: Date.now(),
    });
    return json(200, { blocked: true });
  }

  return json(405, { error: "Method not allowed" });
};
