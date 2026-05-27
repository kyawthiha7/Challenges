<?php
define('JWT_SECRET', 'iloveyou');
define('FLAG', 'THISISTHEFLAG');

// ── JWT helpers (manual HS256, no library needed) ──────────────────────────
function b64url_enc(string $data): string {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}
function b64url_dec(string $data): string {
    $pad = strlen($data) % 4;
    if ($pad) $data .= str_repeat('=', 4 - $pad);
    return base64_decode(strtr($data, '-_', '+/'));
}
function jwt_create(array $payload): string {
    $h   = b64url_enc(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $p   = b64url_enc(json_encode($payload));
    $sig = b64url_enc(hash_hmac('sha256', "$h.$p", JWT_SECRET, true));
    return "$h.$p.$sig";
}
function jwt_verify(string $token): ?array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;
    [$h, $p, $sig] = $parts;
    $expected = b64url_enc(hash_hmac('sha256', "$h.$p", JWT_SECRET, true));
    if (!hash_equals($expected, $sig)) return null;
    $payload = json_decode(b64url_dec($p), true);
    return is_array($payload) ? $payload : null;
}

// ── Accounts ───────────────────────────────────────────────────────────────
$accounts = [
    'guest' => 'guest',
    'user'  => 'user123',
];

// ── State ──────────────────────────────────────────────────────────────────
$error   = '';
$token   = $_COOKIE['token'] ?? '';
$decoded = $token ? jwt_verify($token) : null;

// Logout
if (isset($_GET['logout'])) {
    setcookie('token', '', time() - 1, '/');
    header('Location: /'); exit;
}

// Login
if (!$decoded && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $u = $_POST['username'] ?? '';
    $p = $_POST['password'] ?? '';
    if (isset($accounts[$u]) && $accounts[$u] === $p) {
        $jwt = jwt_create(['username' => $u, 'role' => 'user', 'iat' => time()]);
        setcookie('token', $jwt, 0, '/');
        header('Location: /'); exit;
    }
    $error = 'Invalid username or password.';
}

$is_admin = ($decoded['role'] ?? '') === 'admin';

// For display: split raw token into parts
$token_parts = $token ? explode('.', $token) : [];
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>JWT Lab — Weak Secret</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;min-height:100vh}

/* ── login ── */
.login-wrap{display:flex;justify-content:center;align-items:center;min-height:100vh}
.login-box{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:36px;width:400px}
.login-box h1{color:#58a6ff;font-size:1.2rem;margin-bottom:4px}
.login-box .sub{color:#8b949e;font-size:.78rem;margin-bottom:24px}
label{display:block;color:#8b949e;font-size:.78rem;margin-bottom:5px}
input[type=text],input[type=password]{width:100%;background:#0d1117;border:1px solid #30363d;border-radius:4px;color:#e6edf3;font-family:'Courier New',monospace;font-size:.88rem;padding:9px 12px;margin-bottom:14px;outline:none}
input:focus{border-color:#58a6ff}
.btn{width:100%;background:#1f6feb;border:none;border-radius:4px;color:#fff;font-family:'Courier New',monospace;font-size:.9rem;font-weight:bold;padding:10px;cursor:pointer}
.btn:hover{background:#388bfd}
.err{margin-top:14px;background:#2d1117;border:1px solid #f85149;border-radius:4px;padding:10px 12px;color:#ff7b72;font-size:.82rem}
.login-hint{margin-top:20px;padding-top:16px;border-top:1px solid #21262d;font-size:.73rem;color:#484f58;line-height:1.7}
.login-hint code{color:#8b949e}

/* ── dashboard ── */
.dash{max-width:760px;margin:0 auto;padding:40px 20px}
.topbar{display:flex;justify-content:space-between;align-items:center;margin-bottom:28px}
.topbar h1{color:#58a6ff;font-size:1.2rem}
.topbar a{color:#8b949e;font-size:.78rem;text-decoration:none;border:1px solid #30363d;padding:5px 12px;border-radius:4px}
.topbar a:hover{border-color:#8b949e;color:#c9d1d9}

.section{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:22px;margin-bottom:16px}
.section-title{font-size:.72rem;color:#8b949e;text-transform:uppercase;letter-spacing:.08em;margin-bottom:14px}

/* token display */
.token-raw{word-break:break-all;font-size:.78rem;line-height:1.8;background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:12px}
.token-raw .t-header {color:#ff7b72}
.token-raw .t-dot    {color:#484f58}
.token-raw .t-payload{color:#79c0ff}
.token-raw .t-sig    {color:#3fb950}
.copy-btn{margin-top:8px;background:none;border:1px solid #30363d;border-radius:4px;color:#8b949e;font-family:'Courier New',monospace;font-size:.73rem;padding:4px 12px;cursor:pointer}
.copy-btn:hover{border-color:#58a6ff;color:#58a6ff}

/* decoded */
.decoded-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.decoded-box{background:#0d1117;border:1px solid #30363d;border-radius:4px;padding:12px}
.decoded-box .box-label{font-size:.7rem;color:#484f58;margin-bottom:8px}
.decoded-box pre{font-size:.78rem;color:#e6edf3;white-space:pre-wrap;word-break:break-all}

/* role */
.role-row{display:flex;align-items:center;gap:12px;font-size:.85rem}
.badge{display:inline-block;font-size:.7rem;padding:3px 10px;border-radius:10px;font-weight:bold}
.badge.user {background:#1f2937;color:#58a6ff;border:1px solid #3b82f6}
.badge.admin{background:#2d1117;color:#ff7b72;border:1px solid #f85149}

/* admin area */
.admin-locked{text-align:center;padding:20px;color:#484f58;font-size:.85rem;border:1px dashed #21262d;border-radius:6px}
.admin-locked code{color:#30363d}
.flag-banner{text-align:center;padding:20px;background:#0a2e1a;border:1px solid #238636;border-radius:6px;color:#3fb950;font-size:1.1rem;font-weight:bold;letter-spacing:.08em}

/* hint */
.hint-box{background:#161b22;border:1px solid #30363d;border-left:3px solid #f0883e;border-radius:6px;padding:14px 18px}
.hint-box .hint-title{color:#f0883e;font-size:.75rem;font-weight:bold;margin-bottom:10px}
.hint-box code{font-size:.78rem;color:#8b949e;display:block;line-height:1.9}
</style>
</head>
<body>

<?php if (!$decoded): ?>
<!-- ═══════════════════════════════ LOGIN PAGE ═══════════════════════════════ -->
<div class="login-wrap">
  <div class="login-box">
    <h1>JWT Login</h1>
    <p class="sub">Sign in to receive your JSON Web Token.</p>
    <form method="POST">
      <label>Username</label>
      <input type="text" name="username" autocomplete="off" placeholder="guest">
      <label>Password</label>
      <input type="password" name="password" placeholder="guest">
      <button class="btn" type="submit">Login</button>
    </form>
    <?php if ($error): ?>
    <div class="err"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    <div class="login-hint">
      Accounts: <code>guest:guest</code> &nbsp;/&nbsp; <code>user:user123</code><br>
      Tokens are signed with HS256. The admin account does not have a login — you'll need to forge a token.
    </div>
  </div>
</div>

<?php else: ?>
<!-- ═══════════════════════════════ DASHBOARD ════════════════════════════════ -->
<?php
    $header_b64  = $token_parts[0] ?? '';
    $payload_b64 = $token_parts[1] ?? '';
    $sig_b64     = $token_parts[2] ?? '';

    $header_json  = json_encode(json_decode(b64url_dec($header_b64)),  JSON_PRETTY_PRINT);
    $payload_json = json_encode(json_decode(b64url_dec($payload_b64)), JSON_PRETTY_PRINT);
?>
<div class="dash">
  <div class="topbar">
    <h1>JWT Dashboard</h1>
    <a href="?logout=1">Logout</a>
  </div>

  <!-- Raw token -->
  <div class="section">
    <div class="section-title">Your Token (cookie: token)</div>
    <div class="token-raw">
      <span class="t-header"><?= htmlspecialchars($header_b64) ?></span><span class="t-dot">.</span><span class="t-payload"><?= htmlspecialchars($payload_b64) ?></span><span class="t-dot">.</span><span class="t-sig"><?= htmlspecialchars($sig_b64) ?></span>
    </div>
    <button class="copy-btn" onclick="navigator.clipboard.writeText('<?= htmlspecialchars($token) ?>');this.textContent='Copied!'">Copy token</button>
  </div>

  <!-- Decoded -->
  <div class="section">
    <div class="section-title">Decoded</div>
    <div class="decoded-grid">
      <div class="decoded-box">
        <div class="box-label">Header</div>
        <pre><?= htmlspecialchars($header_json) ?></pre>
      </div>
      <div class="decoded-box">
        <div class="box-label">Payload</div>
        <pre><?= htmlspecialchars($payload_json) ?></pre>
      </div>
    </div>
  </div>

  <!-- Role & admin area -->
  <div class="section">
    <div class="section-title">Access Level</div>
    <div class="role-row">
      <span>Signed in as <strong><?= htmlspecialchars($decoded['username'] ?? '?') ?></strong></span>
      <span class="badge <?= htmlspecialchars($decoded['role'] ?? 'user') ?>"><?= htmlspecialchars($decoded['role'] ?? 'user') ?></span>
    </div>
  </div>

  <div class="section">
    <div class="section-title">Admin Area</div>
    <?php if ($is_admin): ?>
    <div class="flag-banner"><?= FLAG ?></div>
    <?php else: ?>
    <div class="admin-locked">
      This area requires <code>role: admin</code> in the JWT payload.<br>
      Crack the signing secret, forge a token, set it as the <code>token</code> cookie.
    </div>
    <?php endif; ?>
  </div>

  <!-- Hint -->
  <div class="hint-box">
    <div class="hint-title">How to crack it</div>
    <code># hashcat (fast, GPU)</code>
    <code>hashcat -a 0 -m 16500 &lt;token&gt; rockyou.txt</code>
    <code></code>
    <code># john (CPU)</code>
    <code>echo '&lt;token&gt;' > jwt.txt && john --format=HMAC-SHA256 --wordlist=rockyou.txt jwt.txt</code>
    <code></code>
    <code># forge with python (after cracking)</code>
    <code>pip install pyjwt</code>
    <code>python3 -c "import jwt; print(jwt.encode({'username':'admin','role':'admin','iat':0}, '&lt;secret&gt;', algorithm='HS256'))"</code>
  </div>
</div>
<?php endif; ?>

</body>
</html>
