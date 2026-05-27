<?php
$result = ''; $error = '';
$default_xml = '<?xml version="1.0"?>
<user>
  <name>John Doe</name>
</user>';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $xml_input = $_POST['xml'] ?? '';
    if (trim($xml_input) !== '') {
        libxml_use_internal_errors(true);
        $doc = new DOMDocument();
        // LIBXML_NOENT substitutes external entities — dangerous!
        if ($doc->loadXML($xml_input, LIBXML_NOENT | LIBXML_DTDLOAD)) {
            $nodes = $doc->getElementsByTagName('name');
            $result = $nodes->length > 0
                ? htmlspecialchars($nodes->item(0)->textContent)
                : "Parsed OK but no &lt;name&gt; element found.";
        } else {
            $errors = libxml_get_errors();
            $error = htmlspecialchars($errors[0]->message ?? 'Invalid XML');
            libxml_clear_errors();
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>XML Parser — XXE</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:40px 20px}
.wrap{max-width:680px;margin:0 auto}
h1{color:#58a6ff;font-size:1.3rem;margin-bottom:4px}
.sub{color:#8b949e;font-size:.8rem;margin-bottom:24px}
textarea{width:100%;background:#161b22;border:1px solid #30363d;border-radius:4px;color:#e6edf3;font-family:'Courier New',monospace;font-size:.82rem;padding:12px;resize:vertical;outline:none;min-height:180px;margin-bottom:12px}
textarea:focus{border-color:#58a6ff}
button{background:#238636;border:none;border-radius:4px;color:#fff;font-family:'Courier New',monospace;font-size:.9rem;font-weight:bold;padding:10px 28px;cursor:pointer;margin-bottom:18px}
button:hover{background:#2ea043}
.result{background:#0a2e1a;border:1px solid #238636;border-radius:6px;padding:16px;color:#3fb950;font-size:.9rem;margin-bottom:16px}
.result .label{font-size:.75rem;color:#238636;margin-bottom:6px}
.error{background:#2d1117;border:1px solid #f85149;border-radius:6px;padding:14px;color:#ff7b72;font-size:.85rem;margin-bottom:16px}
.info-box{background:#161b22;border:1px solid #30363d;border-left:3px solid #58a6ff;border-radius:6px;padding:14px 18px;margin-bottom:16px;font-size:.8rem;color:#8b949e;line-height:1.7}
.info-box code{color:#79c0ff}
.hint{font-size:.75rem;color:#484f58;border-top:1px solid #21262d;padding-top:14px}
</style>
</head>
<body>
<div class="wrap">
  <h1>XML Name Parser</h1>
  <p class="sub">Submit XML and the server will extract the <code>&lt;name&gt;</code> element.</p>
  <form method="POST">
    <textarea name="xml"><?= htmlspecialchars($_POST['xml'] ?? $default_xml) ?></textarea>
    <button>Parse XML</button>
  </form>
  <?php if ($result): ?>
  <div class="result"><div class="label">Extracted &lt;name&gt;</div><?= $result ?></div>
  <?php endif; ?>
  <?php if ($error): ?>
  <div class="error"><?= $error ?></div>
  <?php endif; ?>
  <div class="info-box">
    Server uses: <code>$doc->loadXML($input, LIBXML_NOENT | LIBXML_DTDLOAD)</code><br>
    The flag is at <code>/flag.txt</code> on the server.
  </div>
  <div class="hint">Hint: Define an external entity pointing to a local file and reference it inside <code>&lt;name&gt;</code>.</div>
</div>
</body>
</html>
