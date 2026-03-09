import crypto from "crypto";

export default async function handler(req, res) {
  const secret = process.env.WEBHOOK_SECRET;
  const signature = req.headers["x-vamsys-signature"];

  console.log("===== WEBHOOK RECEIVED =====");
  console.log("Headers:", req.headers);
  console.log("Body:", JSON.stringify(req.body, null, 2));
  console.log("Event:", req.body?.event);

  if (secret && signature) {
    const expected = crypto
      .createHmac("sha256", secret)
      .update(JSON.stringify(req.body))
      .digest("hex");

    if (signature === expected) {
      console.log("Signature valid");
    } else {
      console.log("Signature mismatch");
    }
  }

  console.log("============================");

  res.status(200).json({ received: true });
}
