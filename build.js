#!/usr/bin/env node
// Usage: node build.js YYYY-MM-DD

const crypto = require("crypto")
const fs = require("fs")

const TARGET_DATE = process.argv[2]

const html = fs.readFileSync("secret_page/page.html", "utf8")

const keyBytes = crypto.pbkdf2Sync(TARGET_DATE, Buffer.from([42]), 1, 32, "sha256")

// Random 12-byte IV
const iv = crypto.randomBytes(12)

// AES-256-GCM encrypt
const cipher = crypto.createCipheriv("aes-256-gcm", keyBytes, iv)
const ciphertext = Buffer.concat([cipher.update(html, "utf8"), cipher.final()])
const authTag = cipher.getAuthTag(); // 16 bytes

// Write: [IV (12 bytes)][ciphertext][auth tag (16 bytes)]
// Web Crypto's decrypt() expects the auth tag appended to the ciphertext,
// so slicing off the first 12 bytes as IV and passing the rest works directly.
const output = Buffer.concat([iv, ciphertext, authTag])
fs.writeFileSync("page.enc", output)

const hash = crypto.createHash("sha256").update(TARGET_DATE).digest("hex")

console.log("page.enc written.")
console.log("\nPaste this into unlock.js:")
console.log(`const EXPECTED_HASH = "${hash}"`)
