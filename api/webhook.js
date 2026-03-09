import crypto from "crypto";

export default async function handler(req, res) {
  const payload = req.body;

  const secret = process.env.WEBHOOK_SECRET;
  const signature = req.headers["x-vamsys-signature"];

  console.log("===== WEBHOOK RECEIVED =====");
  console.log(JSON.stringify(payload, null, 2));

  /*
  -----------------------------
  SIGNATURE VERIFICATION
  -----------------------------
  */

  if (secret && signature) {
    const expected = crypto
      .createHmac("sha256", secret)
      .update(JSON.stringify(payload))
      .digest("hex");

    if (signature !== expected) {
      console.log("Invalid signature");
      return res.status(401).json({ error: "Invalid signature" });
    }

    console.log("Signature valid");
  }

  /*
  -----------------------------
  RESPOND IMMEDIATELY
  -----------------------------
  */

  res.status(200).json({ received: true });

  /*
  -----------------------------
  ASYNC PROCESSING
  -----------------------------
  */

  processWebhook(payload).catch((err) => {
    console.error("Webhook processing failed:", err);
  });
}

/*
----------------------------------
ASYNC PAYLOAD STORAGE
----------------------------------
*/

async function processWebhook(payload) {
  const id = payload.event_id || Date.now();

  // conflict-safe filename
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

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`GitHub API error: ${text}`);
  }

  console.log("Payload stored:", filename);
}
