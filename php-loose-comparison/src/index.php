<?php
session_start();

$flag = "THISISTHEFLAG";

// The stored hash is md5("240610708") = "0e462097431906509019562988736854"
// PHP loose comparison treats "0e..." strings as scientific notation (floats)
// So any string whose md5 starts with "0e" followed only by digits will == this hash
$stored_hash = "0e462097431906509019562988736854";

$message = "";
$message_type = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';

    if ($password === '') {
        $message = "Please enter a password.";
        $message_type = "error";
    } elseif (md5($password) == $stored_hash) {
        $message = "Access granted! Flag: <strong>" . htmlspecialchars($flag) . "</strong>";
        $message_type = "success";
    } else {
        $message = "Wrong password. Hash was: <code>" . md5($password) . "</code>";
        $message_type = "error";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Secure Admin Panel</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background: #0f0f0f;
      color: #e0e0e0;
      font-family: 'Courier New', monospace;
      display: flex;
      justify-content: center;
      align-items: center;
      min-height: 100vh;
    }
    .container {
      background: #1a1a1a;
      border: 1px solid #333;
      border-radius: 6px;
      padding: 40px;
      width: 420px;
    }
    h1 {
      font-size: 1.4rem;
      color: #00ff88;
      margin-bottom: 6px;
    }
    .subtitle {
      font-size: 0.8rem;
      color: #555;
      margin-bottom: 28px;
    }
    label {
      display: block;
      font-size: 0.85rem;
      color: #888;
      margin-bottom: 6px;
    }
    input[type="text"] {
      width: 100%;
      background: #111;
      border: 1px solid #333;
      border-radius: 4px;
      color: #e0e0e0;
      font-family: 'Courier New', monospace;
      font-size: 0.95rem;
      padding: 10px 12px;
      margin-bottom: 16px;
      outline: none;
    }
    input[type="text"]:focus { border-color: #00ff88; }
    button {
      width: 100%;
      background: #00ff88;
      border: none;
      border-radius: 4px;
      color: #0f0f0f;
      cursor: pointer;
      font-family: 'Courier New', monospace;
      font-size: 0.95rem;
      font-weight: bold;
      padding: 10px;
    }
    button:hover { background: #00cc66; }
    .message {
      margin-top: 20px;
      padding: 12px;
      border-radius: 4px;
      font-size: 0.9rem;
      line-height: 1.5;
    }
    .success { background: #0a2e1a; border: 1px solid #00ff88; color: #00ff88; }
    .error   { background: #2e0a0a; border: 1px solid #ff4444; color: #ff6666; }
    .hint {
      margin-top: 24px;
      font-size: 0.75rem;
      color: #444;
      border-top: 1px solid #222;
      padding-top: 16px;
    }
    code { color: #888; }
  </style>
</head>
<body>
  <div class="container">
    <h1>Admin Panel</h1>
    <p class="subtitle">Enter the secret password to retrieve the flag.</p>

    <form method="POST" action="">
      <label for="password">Password</label>
      <input type="text" id="password" name="password" placeholder="enter password..." autocomplete="off">
      <button type="submit">Authenticate</button>
    </form>

    <?php if ($message): ?>
      <div class="message <?= $message_type ?>">
        <?= $message ?>
      </div>
    <?php endif; ?>

    <div class="hint">
      Hint: The password is validated against its MD5 hash using PHP's <code>==</code> operator.<br>
      Stored hash: <code><?= $stored_hash ?></code>
    </div>
  </div>
</body>
</html>
