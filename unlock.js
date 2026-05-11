const EXPECTED_HASH = "REPLACE_WITH_OUTPUT_FROM_BUILD_SCRIPT"

const IV_LENGTH = 12

function getDateString() {
  const now = new Date()
  const y = now.getFullYear()
  const m = String(now.getMonth() + 1).padStart(2, "0")
  const d = String(now.getDate()).padStart(2, "0")
  return `${y}${m}${d}`
}

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
  const dateStr = getDateString()

  const hash = await sha256hex(dateStr)

  if (hash !== EXPECTED_HASH) return

  const key = await deriveKey(dateStr)

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

tryUnlock()
