import crypto from "crypto";

export default async function handler(req, res) {
  const payload = req.body;

  const secret = process.env.WEBHOOK_SECRET;
  const signature = req.headers["x-vamsys-signature"];

  console.log("===== WEBHOOK RECEIVED =====");
  console.log(JSON.stringify(payload, null, 2));

  /*
  --------------------------------
  VERIFY SIGNATURE
  --------------------------------
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
