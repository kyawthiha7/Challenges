<?php
$msg = ''; $type = ''; $link = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $allowed = ['image/jpeg', 'image/png', 'image/gif'];

    // "Security": only check the Content-Type header (client-controlled!)
    if (!in_array($file['type'], $allowed)) {
        $msg = "Error: only JPEG, PNG, and GIF images are accepted.";
        $type = 'error';
    } elseif ($file['error'] !== UPLOAD_ERR_OK) {
        $msg = "Upload error.";
        $type = 'error';
    } else {
        $filename = basename($file['name']);
        $dest = '/var/www/html/uploads/' . $filename;
        if (move_uploaded_file($file['tmp_name'], $dest)) {
            $link = '/uploads/' . htmlspecialchars($filename);
            $msg = "Uploaded: <a href='$link'>$link</a>";
            $type = 'success';
        } else {
            $msg = "Failed to save file.";
            $type = 'error';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Image Upload — File Upload Bypass</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#0d1117;color:#c9d1d9;font-family:'Courier New',monospace;padding:40px 20px}
.wrap{max-width:620px;margin:0 auto}
h1{color:#58a6ff;font-size:1.3rem;margin-bottom:4px}
.sub{color:#8b949e;font-size:.8rem;margin-bottom:24px}
.upload-area{background:#161b22;border:2px dashed #30363d;border-radius:8px;padding:32px;text-align:center;margin-bottom:16px}
.upload-area input[type=file]{display:block;margin:0 auto 16px;color:#8b949e;font-family:'Courier New',monospace;font-size:.85rem}
button{background:#238636;border:none;border-radius:4px;color:#fff;font-family:'Courier New',monospace;font-size:.9rem;font-weight:bold;padding:10px 28px;cursor:pointer}
button:hover{background:#2ea043}
.msg{margin-top:16px;padding:12px;border-radius:4px;font-size:.85rem;line-height:1.6}
.success{background:#0a2e1a;border:1px solid #238636;color:#3fb950}
.success a{color:#3fb950}
.error{background:#2d1117;border:1px solid #f85149;color:#ff7b72}
.filter-box{background:#161b22;border:1px solid #30363d;border-left:3px solid #f0883e;border-radius:6px;padding:14px 18px;margin-bottom:16px}
.filter-box .title{color:#f0883e;font-size:.8rem;font-weight:bold;margin-bottom:6px}
.filter-box code{font-size:.8rem;color:#8b949e;display:block;line-height:1.7}
.hint{font-size:.75rem;color:#484f58;border-top:1px solid #21262d;padding-top:14px;margin-top:8px}
</style>
</head>
<body>
<div class="wrap">
  <h1>Image Upload</h1>
  <p class="sub">Upload product images. Only JPEG, PNG, and GIF are allowed.</p>
  <form method="POST" enctype="multipart/form-data">
    <div class="upload-area">
      <input type="file" name="file">
      <button type="submit">Upload</button>
    </div>
  </form>
  <?php if ($msg): ?>
  <div class="msg <?= $type ?>"><?= $msg ?></div>
  <?php endif; ?>
  <div class="filter-box">
    <div class="title">Validation logic</div>
    <code>$allowed = ['image/jpeg', 'image/png', 'image/gif'];</code>
    <code>if (!in_array($file['type'], $allowed)) { die("Error"); }</code>
  </div>
  <div class="hint">Hint: <code>$_FILES['file']['type']</code> comes directly from the request — the browser (or curl) sets it. The flag is at <code>/flag.txt</code>.</div>
</div>
</body>
</html>
