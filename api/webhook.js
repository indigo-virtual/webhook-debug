import crypto from "crypto";

/**
 * vAMSYS Webhook Handler
 *
 * Implements vAMSYS webhook requirements:
 * - HMAC-SHA256 verification (X-vAMSYS-Signature); never expose WEBHOOK_SECRET client-side.
 * - Respond with 2xx within 3 seconds; process asynchronously after responding.
 * - Idempotency: use event_id to avoid duplicate processing on retries.
 * - HTTPS only (enforced by deployment).
 */

export const config = { api: { bodyParser: false } };

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/** Sanitize event_id for use in file path (alphanumeric, underscore, hyphen only). */
function sanitizeEventId(id) {
  if (typeof id !== "string") return String(Date.now());
  return id.replace(/[^a-zA-Z0-9_-]/g, "_");
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const rawBody = await getRawBody(req);
  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch (e) {
    console.error("Invalid JSON body:", e.message);
    return res.status(400).json({ error: "Invalid JSON" });
  }

  // Validate payload structure (event, event_id per vAMSYS schema)
  if (!payload.event || !payload.event_id) {
    return res.status(400).json({
      error: "Invalid payload",
      message: "Missing required fields: event, event_id",
    });
  }

  const secret = process.env.WEBHOOK_SECRET;
  const signature = req.headers["x-vamsys-signature"];

  /*
   * Signature verification (server-side only). Use raw body — vAMSYS signs
   * the exact bytes sent; re-serializing parsed JSON can break verification.
   */
  if (secret && signature) {
    const expected = crypto
      .createHmac("sha256", secret)
      .update(rawBody, "utf8")
      .digest("hex");
    const receivedSig = signature.replace(/^sha256=/, "");

    if (receivedSig !== expected) {
      console.log("Invalid signature");
      return res.status(401).json({ error: "Invalid signature" });
    }
  } else if (signature && !secret) {
    return res.status(500).json({
      error: "Server misconfiguration",
      message: "WEBHOOK_SECRET not set",
    });
  }

  // Respond immediately to avoid timeout (vAMSYS requires response within 3s)
  res.status(200).json({ received: true });

  // --- Async processing after response (queue-style) ---
  console.log("===== WEBHOOK RECEIVED =====");
  console.log("event:", payload.event, "event_id:", payload.event_id);
  console.log(JSON.stringify(payload, null, 2));

  const eventId = payload.event_id;
  const filename = `payloads/${sanitizeEventId(eventId)}.json`;
  const content = Buffer.from(JSON.stringify(payload, null, 2)).toString(
    "base64",
  );
  const owner = process.env.GITHUB_OWNER;
  const repo = process.env.GITHUB_REPO;
  const token = process.env.GITHUB_TOKEN;

  if (!owner || !repo || !token) {
    console.error("GitHub env missing (GITHUB_OWNER, GITHUB_REPO, GITHUB_TOKEN)");
    console.log("============================");
    return;
  }

  try {
    const baseUrl = `https://api.github.com/repos/${owner}/${repo}/contents`;
    const getRes = await fetch(`${baseUrl}/${filename}`, {
      headers: { Authorization: `Bearer ${token}` },
    });

    // Idempotency: skip if we already stored this event_id (handles retries)
    if (getRes.ok) {
      console.log("Already stored (idempotent skip):", filename);
      console.log("============================");
      return;
    }

    if (getRes.status !== 404) {
      const text = await getRes.text();
      console.error("GitHub GET failed:", getRes.status, text);
      console.log("============================");
      return;
    }

    const putRes = await fetch(`${baseUrl}/${filename}`, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: `Webhook ${payload.event} ${eventId}`,
        content,
      }),
    });

    const result = await putRes.text();
    console.log("GitHub API response:", putRes.status, result);

    if (!putRes.ok) {
      throw new Error(result);
    }
    console.log("Payload stored:", filename);
  } catch (error) {
    console.error("Failed to store payload:", error);
  }

  console.log("============================");
}
