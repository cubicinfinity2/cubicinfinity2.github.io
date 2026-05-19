const EXPECTED_HASH = "13387e7ebe8633ac4689973054ba16df67c28a8638fbde05d6629dbe556cc988"

const IV_LENGTH = 12

async function sha256hex(str) {
  const bytes = new TextEncoder().encode(str)
  const buf = await crypto.subtle.digest("SHA-256", bytes)
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}

async function deriveKey(dateStr) {
  const raw = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(dateStr),
    "PBKDF2",
    false,
    ["deriveKey"]
  )
  return crypto.subtle.deriveKey(
    {name: "PBKDF2", salt: new Uint8Array([42]), iterations: 1, hash: "SHA-256"},
    raw,
    {name: "AES-GCM", length: 256},
    false,
    ["decrypt"]
  )
}

async function tryUnlock() {
  const date = document.getElementById('date').value;
  console.log(date)

  const hash = await sha256hex(date)
  console.log(hash)
  if (hash !== EXPECTED_HASH) return
  console.log("hash matches")

  const key = await deriveKey(date)

  const response = await fetch("page.enc")
  const buffer = await response.arrayBuffer()
  const data = new Uint8Array(buffer)

  // [IV: 12 bytes][ciphertext + auth tag]
  const iv = data.slice(0, IV_LENGTH)
  const ciphertext = data.slice(IV_LENGTH)

  let decrypted
  try {
    decrypted = await crypto.subtle.decrypt({name: "AES-GCM", iv}, key, ciphertext)
  } catch {
    return
  }

  const html = new TextDecoder().decode(decrypted)
  document.open()
  document.write(html)
  document.close()
}
