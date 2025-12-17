import crypto from "crypto";
import { Redis } from "@upstash/redis";
import { keccak256, toUtf8Bytes } from "ethers";

/**
 * IMPORTANT: Disable Next.js body parsing so we can verify Shopify signature
 * against the EXACT raw request bytes.
 */
export const config = {
  api: {
    bodyParser: false,
  },
};

function timingSafeEqualStr(a = "", b = "") {
  const aa = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (aa.length !== bb.length) return false;
  return crypto.timingSafeEqual(aa, bb);
}

/**
 * Verify Shopify webhook HMAC:
 * header X-Shopify-Hmac-Sha256 = base64(HMAC_SHA256(rawBody, secret))
 */
function verifyShopifyHmac({ rawBody, secret, hmacHeader }) {
  if (!secret || !hmacHeader) return false;

  const digest = crypto
    .createHmac("sha256", secret)
    .update(rawBody)
    .digest("base64");

  return timingSafeEqualStr(digest, hmacHeader);
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

/**
 * Build a privacy-safe receipt object (NO full address, NO name).
 * Keep it consistent so the hash is stable.
 */
function buildCanonicalReceipt(payload) {
  const lineItems =
    (payload?.line_items || []).map((li) => ({
      sku: li?.sku || null,
      title: li?.title || null,
      quantity: li?.quantity || 0,
      price: li?.price || null,
      variant_id: li?.variant_id || null,
      product_id: li?.product_id || null,
    })) ?? [];

  return {
    // IDs
    order_id: payload?.id ?? null,
    order_number: payload?.order_number ?? null,
    admin_graphql_api_id: payload?.admin_graphql_api_id ?? null,

    // Money
    currency: payload?.currency ?? null,
    total_price: payload?.total_price ?? null,
    subtotal_price: payload?.subtotal_price ?? null,
    total_tax: payload?.total_tax ?? null,
    total_discounts: payload?.total_discounts ?? null,

    // Timing
    created_at: payload?.created_at ?? null,
    processed_at: payload?.processed_at ?? null,

    // Store + status
    financial_status: payload?.financial_status ?? null,
    fulfillment_status: payload?.fulfillment_status ?? null,

    // Minimal shipping context (safe-ish)
    ship_country: payload?.shipping_address?.country_code ?? null,
    ship_province: payload?.shipping_address?.province_code ?? null,
    ship_city: payload?.shipping_address?.city ?? null,

    // Items
    line_items: lineItems,
  };
}

/**
 * Deterministic JSON stringify (stable key order) so hash is consistent.
 */
function stableStringify(obj) {
  const allKeys = [];
  JSON.stringify(obj, (key, value) => {
    allKeys.push(key);
    return value;
  });
  allKeys.sort();

  return JSON.stringify(obj, allKeys);
}

/**
 * Stub: get or create a customer wallet.
 * Replace this body with Crossmint "getOrCreate wallet by email" when ready.
 */
async function getOrCreateCustomerWallet({ redis, email }) {
  const emailHash = sha256Hex(email.toLowerCase().trim());
  const existing = await redis.get(`cust:wallet:${emailHash}`);
  if (existing) return { emailHash, walletAddress: existing, created: false };

  // TODO: Replace with real wallet creation (Crossmint / custodial)
  // For now we store a placeholder so the pipeline works end-to-end.
  const placeholder = `pending_wallet_for_${emailHash.slice(0, 10)}`;

  await redis.set(`cust:wallet:${emailHash}`, placeholder);
  return { emailHash, walletAddress: placeholder, created: true };
}

export default async function handler(req, res) {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ ok: false, error: "Method not allowed" });
  }

  const secret = process.env.SHOPIFY_WEBHOOK_SECRET;
  if (!secret) {
    return res.status(500).json({ ok: false, error: "Missing SHOPIFY_WEBHOOK_SECRET" });
  }

  const redis = Redis.fromEnv();

  // Read raw body bytes (required for signature validation)
  const rawBodyBuf = await readRawBody(req);
  const hmacHeader = req.headers["x-shopify-hmac-sha256"];

  const valid = verifyShopifyHmac({
    rawBody: rawBodyBuf,
    secret,
    hmacHeader: typeof hmacHeader === "string" ? hmacHeader : "",
  });

  if (!valid) {
    return res.status(401).json({ ok: false, error: "Invalid webhook signature" });
  }

  let payload;
  try {
    payload = JSON.parse(rawBodyBuf.toString("utf8"));
  } catch {
    return res.status(400).json({ ok: false, error: "Invalid JSON" });
  }

  const topic = req.headers["x-shopify-topic"] || null;

  // Order identifier (Shopify REST webhooks usually include payload.id)
  const orderId = payload?.id || payload?.order_id || null;
  if (!orderId) {
    return res.status(400).json({ ok: false, error: "Missing order id" });
  }

  // ---- Idempotency: only process each order once ----
  const lockKey = `order:processed:${orderId}`;
  const already = await redis.get(lockKey);
  if (already) {
    // Return 200 so Shopify stops retrying
    return res.status(200).json({ ok: true, deduped: true });
  }

  // ---- Wallet mapping (create once, reuse) ----
  const email = payload?.email || payload?.customer?.email || null;
  let wallet = null;
  if (email) {
    wallet = await getOrCreateCustomerWallet({ redis, email });
  }

  // ---- Receipt + onchain-proof hash ----
  const receiptObj = buildCanonicalReceipt(payload);
  const receiptJson = stableStringify(receiptObj);
  const receiptHash = keccak256(toUtf8Bytes(receiptJson)); // 0x...

  // Store in KV (full receipt offchain, hash is what will go onchain)
  await redis.set(`order:receipt:${orderId}`, {
    orderId,
    topic,
    receiptHash,
    receipt: receiptObj,
    emailHash: wallet?.emailHash || null,
    walletAddress: wallet?.walletAddress || null,
    createdAt: new Date().toISOString(),
  });

  // Mark processed (idempotency lock)
  await redis.set(lockKey, "1");

  console.log("✅ Shopify webhook processed:", {
    topic,
    orderId,
    total_price: payload?.total_price,
    currency: payload?.currency,
    receiptHash,
    walletAddress: wallet?.walletAddress || null,
    walletCreated: wallet?.created || false,
  });

  // NEXT STEP (coming right after this):
  // - write {orderId, receiptHash, walletAddress, timestamp} on Base
  // - save tx hash back into KV: order:tx:${orderId}
  return res.status(200).json({ ok: true, orderId, receiptHash });
}

