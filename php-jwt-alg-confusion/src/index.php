<?php
// ── Route: /pubkey ─────────────────────────────────────────────────────────
// Realistic JWKS-style endpoint — the public key is intentionally exposed
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
if ($uri === '/pubkey') {
    header('Content-Type: text/plain; charset=utf-8');
    readfile('/keys/public.pem');
    exit;
}

define('FLAG',        'THISISTHEFLAG');
define('PRIV_KEY',    '/keys/private.pem');
define('PUB_KEY',     '/keys/public.pem');

// ── JWT helpers ────────────────────────────────────────────────────────────
function b64url_enc(string $d): string {
    return rtrim(strtr(base64_encode($d), '+/', '-_'), '=');
}
function b64url_dec(string $d): string {
    $r = strlen($d) % 4;
    if ($r) $d .= str_repeat('=', 4 - $r);
    return base64_decode(strtr($d, '-_', '+/'));
}

function jwt_issue(array $payload): string {
    $h = b64url_enc(json_encode(['alg' => 'RS256', 'typ' => 'JWT']));
    $p = b64url_enc(json_encode($payload));
    openssl_sign("$h.$p", $raw_sig, file_get_contents(PRIV_KEY), OPENSSL_ALGO_SHA256);
    return "$h.$p." . b64url_enc($raw_sig);
}

function jwt_verify(string $token): ?array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$h, $p, $sig] = $parts;

    $header = json_decode(b64url_dec($h), true);
    $alg    = $header['alg'] ?? '';
    $pubkey = file_get_contents(PUB_KEY);

    if ($alg === 'RS256') {
        // Correct: verify with RSA public key
        if (openssl_verify("$h.$p", b64url_dec($sig), $pubkey, OPENSSL_ALGO_SHA256) !== 1)
            return null;

    } elseif ($alg === 'HS256') {
        // !! VULNERABLE: RSA public key treated as HMAC secret !!
        // A symmetric (HS256) token signed with the RSA public key bytes
        // will verify correctly here — algorithm confusion.
        $expected = b64url_enc(hash_hmac('sha256', "$h.$p", $pubkey, true));
        if (!hash_equals($expected, $sig)) return null;

    } else {
        return null; // alg:none and unknown algorithms rejected
    }

    $claims = json_decode(b64url_dec($p), true);
    return is_array($claims) ? $claims : null;
}

// ── Accounts ───────────────────────────────────────────────────────────────
$accounts = [
    'guest' => 'guest',
    'user'  => 'user123',
];

// ── State ──────────────────────────────────────────────────────────────────
$error   = '';
$token   = $_COOKIE['token'] ?? '';
$claims  = $token ? jwt_verify($token) : null;

if (isset($_GET['logout'])) {
    setcookie('token', '', time() - 1, '/');
    header('Location: /'); exit;
}

if (!$claims && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    if (isset($accounts[$u]) && $accounts[$u] === $p) {
        $jwt = jwt_issue(['username' => $u, 'role' => 'user', 'iat' => time()]);
        setcookie('token', $jwt, 0, '/');
        header('Location: /'); exit;
    }
    $error = 'Invalid credentials.';
}

$is_admin = ($claims['role'] ?? '') === 'admin';
$parts    = $token ? explode('.', $token) : ['','',''];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SecureVault — JWT Auth</title>
<!-- Key endpoint: /pubkey -->
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;min-height:100vh}

.login-wrap{display:flex;justify-content:center;align-items:center;min-height:100vh}
.login-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:36px;width:400px}
.login-box h1{color:#e6edf3;font-size:1.2rem;margin-bottom:4px}
.login-box .sub{color:#8b949e;font-size:.78rem;margin-bottom:24px}
label{display:block;color:#8b949e;font-size:.78rem;margin-bottom:5px}
input[type=text],input[type=password]{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#e6edf3;font-family:'Courier New',monospace;font-size:.88rem;padding:9px 12px;margin-bottom:14px;outline:none}
input:focus{border-color:#388bfd}
.btn{width:100%;background:#1f6feb;border:none;border-radius:4px;color:#fff;font-family:'Courier New',monospace;font-size:.9rem;font-weight:bold;padding:10px;cursor:pointer}
.btn:hover{background:#388bfd}
.err{margin-top:14px;background:#2d1117;border:1px solid #f85149;border-radius:4px;padding:10px 12px;color:#ff7b72;font-size:.82rem}
.login-note{margin-top:20px;padding-top:16px;border-top:1px solid #21262d;font-size:.72rem;color:#484f58}
.login-note code{color:#8b949e}

.dash{max-width:800px;margin:0 auto;padding:40px 20px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px}
.topbar h1{color:#e6edf3;font-size:1.15rem}
.topbar a{color:#8b949e;font-size:.78rem;text-decoration:none;border:1px solid #30363d;padding:5px 12px;border-radius:4px}
.topbar a:hover{border-color:#8b949e;color:#c9d1d9}

.panel{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:22px;margin-bottom:16px}
.panel-title{font-size:.7rem;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}

.token-display{word-break:break-all;font-size:.77rem;line-height:1.9;background:#010409;border:1px solid #21262d;border-radius:4px;padding:14px}
.t-h{color:#ff7b72}.t-dot{color:#30363d}.t-p{color:#79c0ff}.t-s{color:#3fb950}
.copy-btn{margin-top:8px;background:none;border:1px solid #30363d;border-radius:4px;color:#8b949e;font-family:'Courier New',monospace;font-size:.72rem;padding:4px 12px;cursor:pointer}
.copy-btn:hover{border-color:#388bfd;color:#388bfd}

.grid2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.json-box{background:#010409;border:1px solid #21262d;border-radius:4px;padding:12px}
.json-box .jlabel{font-size:.68rem;color:#484f58;margin-bottom:8px}
.json-box pre{font-size:.77rem;color:#e6edf3;white-space:pre-wrap;word-break:break-all;line-height:1.6}

.meta-row{display:flex;align-items:center;gap:14px;font-size:.85rem;color:#8b949e}
.meta-row strong{color:#e6edf3}
.badge{display:inline-block;font-size:.7rem;padding:3px 10px;border-radius:10px;font-weight:bold;letter-spacing:.03em}
.badge.user {background:#0d1b2a;color:#58a6ff;border:1px solid #1f3a5f}
.badge.admin{background:#2d1117;color:#ff7b72;border:1px solid #6e1a1a}

.flag-banner{text-align:center;padding:22px;background:#0a2e1a;border:1px solid #238636;border-radius:6px;color:#3fb950;font-size:1.1rem;font-weight:bold;letter-spacing:.1em}
.admin-locked{text-align:center;padding:24px;border:1px dashed #21262d;border-radius:6px;color:#30363d;font-size:.85rem;line-height:1.8}
.admin-locked code{color:#21262d}

.alg-badge{display:inline-block;background:#1c2128;border:1px solid #30363d;border-radius:4px;color:#f0883e;font-size:.72rem;padding:3px 10px;font-weight:bold;letter-spacing:.05em}
</style>
</head>
<body>

<?php if (!$claims): ?>
<div class="login-wrap">
  <div class="login-box">
    <h1>SecureVault</h1>
    <p class="sub">Authentication required. Credentials needed to proceed.</p>
    <form method="POST">
      <label>Username</label>
      <input type="text" name="username" autocomplete="off">
      <label>Password</label>
      <input type="password" name="password">
      <button class="btn">Sign in</button>
    </form>
    <?php if ($error): ?>
    <div class="err"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <div class="login-note">
      Available: <code>guest:guest</code> &nbsp;·&nbsp; <code>user:user123</code>
    </div>
  </div>
</div>

<?php else:
    $hdr_json = json_encode(
        json_decode(b64url_dec($parts[0]), true),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    );
    $pay_json = json_encode(
        json_decode(b64url_dec($parts[1]), true),
        JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
    );
?>
<div class="dash">
  <div class="topbar">
    <h1>SecureVault &mdash; Dashboard</h1>
    <a href="?logout=1">Sign out</a>
  </div>

  <div class="panel">
    <div class="panel-title">Session Token &nbsp;<span class="alg-badge">RS256</span></div>
    <div class="token-display">
      <span class="t-h"><?= htmlspecialchars($parts[0]) ?></span><span class="t-dot">.</span><span class="t-p"><?= htmlspecialchars($parts[1]) ?></span><span class="t-dot">.</span><span class="t-s"><?= htmlspecialchars($parts[2]) ?></span>
    </div>
    <button class="copy-btn" onclick="navigator.clipboard.writeText(<?= json_encode($token) ?>);this.textContent='Copied!'">Copy token</button>
  </div>

  <div class="panel">
    <div class="panel-title">Decoded</div>
    <div class="grid2">
      <div class="json-box"><div class="jlabel">Header</div><pre><?= htmlspecialchars($hdr_json) ?></pre></div>
      <div class="json-box"><div class="jlabel">Payload</div><pre><?= htmlspecialchars($pay_json) ?></pre></div>
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">Identity</div>
    <div class="meta-row">
      <span>Signed in as <strong><?= htmlspecialchars($claims['username'] ?? '?') ?></strong></span>
      <span class="badge <?= htmlspecialchars($claims['role'] ?? 'user') ?>"><?= htmlspecialchars($claims['role'] ?? 'user') ?></span>
    </div>
  </div>

  <div class="panel">
    <div class="panel-title">Restricted Area</div>
    <?php if ($is_admin): ?>
    <div class="flag-banner"><?= FLAG ?></div>
    <?php else: ?>
    <div class="admin-locked">
      Requires <code>"role": "admin"</code><br>
      This endpoint is not accessible to your current role.
    </div>
    <?php endif; ?>
  </div>
</div>
<?php endif; ?>

</body>
</html>
