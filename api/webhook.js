import crypto from "crypto";

// Require raw body for HMAC verification (sender signs exact bytes received).
export const config = { api: { bodyParser: false } };

function getRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
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

  const secret = process.env.WEBHOOK_SECRET;
  const signature = req.headers["x-vamsys-signature"];

  console.log("===== WEBHOOK RECEIVED =====");
  console.log("event:", payload.event, "event_id:", payload.event_id);
  console.log(JSON.stringify(payload, null, 2));

  /*
  --------------------------------
  VERIFY SIGNATURE
  --------------------------------
  Must use the raw body (exact bytes sent). Re-serializing parsed JSON
  can change key order/whitespace and break HMAC verification.
  */

  if (secret && signature) {
    const expected = crypto
      .createHmac("sha256", secret)
      .update(rawBody, "utf8")
      .digest("hex");

    // Some senders use "sha256=hexdigest" format
    const receivedSig = signature.replace(/^sha256=/, "");

    if (receivedSig !== expected) {
      console.log("Invalid signature");
      return res.status(401).json({ error: "Invalid signature" });
    }

    console.log("Signature valid");
  }

  /*
  --------------------------------
  SAVE PAYLOAD TO GITHUB
  --------------------------------
  */

  try {
    const id = payload.event_id || Date.now();

    // prevents GitHub 409 conflicts
    const filename = `payloads/${id}-${Date.now()}.json`;

    const content = Buffer.from(JSON.stringify(payload, null, 2)).toString(
      "base64",
    );

    const url = `https://api.github.com/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/contents/${filename}`;

    const response = await fetch(url, {
      method: "PUT",
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        message: `Webhook payload ${id}`,
        content: content,
      }),
    });

    const result = await response.text();

    console.log("GitHub API response:", result);

    if (!response.ok) {
      throw new Error(result);
    }

    console.log("Payload stored:", filename);
  } catch (error) {
    console.error("Failed to store payload:", error);
  }

  console.log("============================");

  /*
  --------------------------------
  RESPOND TO VAMSYS
  --------------------------------
  */

  res.status(200).json({ received: true });
}
