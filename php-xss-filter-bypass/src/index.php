<?php
// Flag is stored in a cookie — steal it with XSS
setcookie('flag', 'THISISTHEFLAG2', 0, '/');

function waf($input) {
    // Block <script> tags
    $input = str_ireplace('<script>', '', $input);
    $input = str_ireplace('</script>', '', $input);
    // Block javascript: protocol
    $input = str_ireplace('javascript:', '', $input);
    return $input;
}

$query = '';
$searched = false;

if (isset($_GET['q'])) {
    $searched = true;
    $query = waf($_GET['q']);
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Search — XSS Lab</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0d1117;
      color: #c9d1d9;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
      padding: 40px 20px;
    }
    .wrapper { max-width: 700px; margin: 0 auto; }
    h1 { font-size: 1.5rem; color: #58a6ff; margin-bottom: 6px; }
    .subtitle { font-size: 0.85rem; color: #8b949e; margin-bottom: 32px; }

    .search-box {
      display: flex;
      gap: 8px;
      margin-bottom: 28px;
    }
    input[type="text"] {
      flex: 1;
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      color: #c9d1d9;
      font-size: 1rem;
      padding: 10px 14px;
      outline: none;
    }
    input[type="text"]:focus { border-color: #58a6ff; }
    button {
      background: #238636;
      border: none;
      border-radius: 6px;
      color: #fff;
      cursor: pointer;
      font-size: 0.95rem;
      padding: 10px 20px;
    }
    button:hover { background: #2ea043; }

    .result {
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 6px;
      padding: 20px;
      margin-bottom: 24px;
    }
    .result-label { font-size: 0.8rem; color: #8b949e; margin-bottom: 8px; }
    .result-value { font-size: 1rem; color: #e6edf3; word-break: break-all; }

    .waf-box {
      background: #161b22;
      border: 1px solid #30363d;
      border-left: 3px solid #f0883e;
      border-radius: 6px;
      padding: 16px 20px;
      margin-bottom: 24px;
    }
    .waf-title { font-size: 0.85rem; color: #f0883e; margin-bottom: 10px; font-weight: bold; }
    .waf-box code {
      display: block;
      font-size: 0.85rem;
      color: #8b949e;
      line-height: 1.8;
    }

    .goal-box {
      background: #0d1117;
      border: 1px solid #30363d;
      border-left: 3px solid #58a6ff;
      border-radius: 6px;
      padding: 16px 20px;
    }
    .goal-box p { font-size: 0.85rem; color: #8b949e; line-height: 1.6; }
    .goal-box code { color: #79c0ff; }
  </style>
</head>
<body>
  <div class="wrapper">
    <h1>Search Portal</h1>
    <p class="subtitle">Search anything. Your query will be reflected below.</p>

    <form method="GET" action="">
      <div class="search-box">
        <input type="text" name="q" value="<?= htmlspecialchars($_GET['q'] ?? '') ?>" placeholder="Search...">
        <button type="submit">Search</button>
      </div>
    </form>

    <?php if ($searched): ?>
    <div class="result">
      <div class="result-label">Results for:</div>
      <div class="result-value"><?= $query ?></div>
    </div>
    <?php endif; ?>

    <div class="waf-box">
      <div class="waf-title">WAF Rules (source)</div>
      <code>str_ireplace('&lt;script&gt;',  '', $input)</code>
      <code>str_ireplace('&lt;/script&gt;', '', $input)</code>
      <code>str_ireplace('javascript:',   '', $input)</code>
    </div>

    <div class="goal-box">
      <p>
        The flag is stored in your cookie (<code>document.cookie</code>).<br>
        Bypass the WAF and execute JavaScript to retrieve it.
      </p>
    </div>
  </div>
</body>
</html>
