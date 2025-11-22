const fetch = require("node-fetch");

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
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Allow-Methods": "POST,OPTIONS",
};

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
