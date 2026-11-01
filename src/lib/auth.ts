import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";

const COOKIE = "odyssey_session";
const secret = () => new TextEncoder().encode(process.env.SESSION_SECRET!);

export function buildMessage(address: string, nonce: string) {
  return `Sign in to CKB Odyssey\nAddress: ${address}\nNonce: ${nonce}`;
}

export async function createSession(playerId: string) {
  const token = await new SignJWT({})
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(playerId)
    .setIssuedAt()
    .setExpirationTime("30d")
    .sign(secret());

  (await cookies()).set(COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
    maxAge: 60 * 60 * 24 * 30,
  });
}

export async function getSessionPlayerId(): Promise<string | null> {
  const token = (await cookies()).get(COOKIE)?.value;
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, secret());
    return payload.sub ?? null;
  } catch {
    return null;
  }
}

export async function clearSession() {
  (await cookies()).delete(COOKIE);
}