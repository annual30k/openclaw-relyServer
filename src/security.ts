import { createHash, createHmac, randomBytes, randomUUID, timingSafeEqual } from "crypto";

export function nowIso(): string {
  return new Date().toISOString();
}

export function addSeconds(date: Date, seconds: number): string {
  return new Date(date.getTime() + seconds * 1000).toISOString();
}

export function sha256(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

export function randomSecret(bytes = 24): string {
  return randomBytes(bytes).toString("base64url");
}

export function randomCode(length = 6): string {
  let value = "";
  while (value.length < length) {
    value += Math.floor(Math.random() * 10).toString();
  }
  return value.slice(0, length);
}

export function gatewayId(): string {
  return `gw_${randomUUID().replace(/-/g, "").slice(0, 12)}`;
}

export function gatewayCode(): string {
  return randomUUID().replace(/-/g, "").slice(0, 8);
}

export function signToken(payload: Record<string, unknown>, secret: string): string {
  const encoded = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${signature}`;
}

export function verifyToken<T>(token: string, secret: string): T | null {
  const [encoded, signature] = token.split(".");
  if (!encoded || !signature) return null;
  const expected = createHmac("sha256", secret).update(encoded).digest("base64url");
  const left = Buffer.from(signature);
  const right = Buffer.from(expected);
  if (left.length !== right.length || !timingSafeEqual(left, right)) return null;
  try {
    return JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as T;
  } catch {
    return null;
  }
}

export function safeJsonParse<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export function maskSensitive(input: unknown): string {
  if (input == null) return "{}";
  const visited = new WeakSet<object>();
  const redact = (value: unknown): unknown => {
    if (!value || typeof value !== "object") return value;
    if (visited.has(value as object)) return "[Circular]";
    visited.add(value as object);
    if (Array.isArray(value)) return value.map(redact);
    const out: Record<string, unknown> = {};
    for (const [key, current] of Object.entries(value as Record<string, unknown>)) {
      if (/(secret|token|password|apiKey|authorization|content)/i.test(key)) {
        out[key] = "[REDACTED]";
      } else {
        out[key] = redact(current);
      }
    }
    return out;
  };
  return JSON.stringify(redact(input));
}
