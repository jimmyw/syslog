import { createHash, timingSafeEqual } from "node:crypto";

export function verifyS256(verifier, challenge) {
  if (typeof verifier !== "string" || typeof challenge !== "string") return false;
  const a = Buffer.from(createHash("sha256").update(verifier).digest("base64url"));
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}
