import crypto from "crypto";

export default async function handler(req, res) {
  const payload = req.body;

  const secret = process.env.WEBHOOK_SECRET;
  const signature = req.headers["x-vamsys-signature"];

  console.log("===== WEBHOOK RECEIVED =====");
  console.log("Headers:", req.headers);
  console.log("Body:", JSON.stringify(payload, null, 2));
  console.log("Event:", payload?.event);

  if (secret && signature) {
    const expected = crypto
      .createHmac("sha256", secret)
      .update(JSON.stringify(payload))
      .digest("hex");

    if (signature === expected) {
      console.log("Signature valid");
    } else {
      console.log("Signature mismatch");
    }
  }

  console.log("============================");

  /*
  -----------------------------
  SAVE PAYLOAD TO GITHUB
  -----------------------------
  */

  const id = payload.event_id || Date.now();

  // 2-line conflict fix: add timestamp to filename
  const filename = `payloads/${id}-${Date.now()}.json`;

  const content = Buffer.from(JSON.stringify(payload, null, 2)).toString(
    "base64",
  );

  const url = `https://api.github.com/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/contents/${filename}`;

  await fetch(url, {
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

  res.status(200).json({ received: true });
}
