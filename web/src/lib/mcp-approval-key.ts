export async function inspectApprovalKey(input: string) {
  const publicKeySpki = input.trim();
  // Standard DER SPKI for an uncompressed P-256 public point.
  if (publicKeySpki.length !== 124 || !publicKeySpki.startsWith("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE")) {
    throw new Error("Invalid approval public key");
  }
  const der = atob(publicKeySpki);
  if (der.length !== 91 || btoa(der) !== publicKeySpki) throw new Error("Invalid approval public key");
  const bytes = Uint8Array.from(der, (c) => c.charCodeAt(0));
  await crypto.subtle.importKey("spki", bytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
  const fingerprint = Array.from(hash, b => b.toString(16).padStart(2, "0")).join("");
  return { publicKeySpki, fingerprint };
}
