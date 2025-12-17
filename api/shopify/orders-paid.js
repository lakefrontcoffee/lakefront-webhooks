// api/shopify/orders-paid.js
const crypto = require("crypto");

/**
 * Verify Shopify webhook HMAC.
 * Shopify sends base64(HMAC_SHA256(rawBody, secret)) in X-Shopify-Hmac-Sha256
 */
function verifyShopifyHmac({ rawBody, secret, hmacHeader }) {
  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody, "utf8")
    .digest("base64");

  // Timing-safe compare
  const a = Buffer.from(digest, "utf8");
  const b = Buffer.from(hmacHeader || "", "utf8");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
  if (!secret) return res.status(500).json({ ok: false, error: "Missing SHOPIFY_WEBHOOK_SECRET" });

  // Vercel Node functions give you the raw body on req.body only if you disable parsing.
  // So we reconstruct raw body safely:
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  const rawBody = Buffer.concat(chunks).toString("utf8");

  const hmacHeader = req.headers["x-shopify-hmac-sha256"];
  const valid = verifyShopifyHmac({ rawBody, secret, hmacHeader });

  if (!valid) return res.status(401).json({ ok: false, error: "Invalid webhook signature" });

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return res.status(400).json({ ok: false, error: "Invalid JSON" });
  }

  // ---- Idempotency key (we’ll prevent double-mints later with storage) ----
  const orderId = payload?.id || payload?.order_id || payload?.admin_graphql_api_id || null;

  // TODO (next step): store receipt JSON + hash, mint onchain receipt NFT, etc.
  console.log("✅ Shopify webhook received:", {
    topic: req.headers["x-shopify-topic"],
    orderId,
    total_price: payload?.total_price,
    currency: payload?.currency,
  });

  return res.status(200).json({ ok: true });
}
