# Desires Hack The Box WriteUp
Desires is an easy web challenge from hackthebox . 
It's a web app built with a Go backend for the main service and a Node.js module for SSO (single sign-on) handling authentication. The goal is to escalate privileges to admin and grab the flag from the `/user/admin` endpoint.


## Initial Setup and High-Level Overview

The app lets users register, log in, and upload ZIP archives  . Uploaded archives are extracted to `./files/{username}`.  There's an admin page at `/user/admin` that renders `admin.html` with the flag if your role is "admin." The SSO part (Node.js in `index.js`) uses SQLite for users and bcrypt for passwords—pretty standard, but the Go side (`http.go`, `sessions.go`, etc.) handles sessions in a weird way. 

### Observations in Registration

First, I notice the registration in `http.go`'s `RegisterHandler`:   It checks if the username contains `/\.`, rejecting if so. That's a red flag—why filter paths? Maybe to prevent directory traversal in filenames later. But it's only during registration, and we can choose clean usernames, so not a blocker yet. Registration calls the Node SSO via HTTP POST to `/register`, storing users with role "user."

### Quirks in Login

Now, login in `LoginHandler`: This is where things get quirky. Before even checking credentials, it generates a session ID as SHA256 of the current Unix timestamp (no salt or randomness—`fmt.Sprintf("%x", sha256.Sum256([]byte(strconv.FormatInt(time.Now().Unix(), 10))))`). Then it calls `PrepareSession`, which stuffs that ID into Redis with the username as the key. Only after that does it validate credentials via POST to SSO's `/login`. If valid, it creates a JSON session file in `/tmp/sessions/{username}/{sessionID}` with `{"username":..., "id":..., "role":"user"}`, sets cookies for session and username, and redirects.

**Hold up—why set Redis before validation?** If I do a failed login, Redis still gets updated, but no file is created. That's exploitable: I can control Redis mappings for any username without authenticating. And session IDs are predictable from timestamps? We can snag the server's time from HTTP "Date" headers. This smells like a race or forgery opportunity.

### Middleware Vulnerabilities

Next, the middleware `SessionMiddleware` for protected routes like `/user/*`: It grabs username and session from cookies, but ignores the session value—instead, it queries Redis with the username to get the "real" session ID, then reads the JSON from `/tmp/sessions/{username}/{that ID}`. It locals the parsed user struct (with role) for the request. So, auth trusts Redis + file, not the database role. If I can forge a session file with `"role":"admin"` and control Redis to point to it, I'm admin. But how to write that file? No direct file access.

## Spotting the Upload Vulnerability

Shifting to uploads in `UploadEnigma`: After login, you can POST a file "archive" to `/user/upload`. It saves as UUID-named file in `./uploads`, then extracts with `archiver.Unarchive` to `./files/{username}`. No sanitization on paths inside the archive—classic Zip Slip potential. The library is `mholt/archiver/v3`, which has CVE-2024-0406: It mishandles symlinks in TAR archives, allowing path traversal and arbitrary writes if the app has perms (here, to `/tmp`, which is writable).

### Why TAR over ZIP?

The PoC shows TAR symlinks are followed during extraction, letting us escape `./files/{username}` to anywhere, like `/tmp/sessions`. But in ZIP, duplicates (symlink + file at same path) error out, as we saw in testing. So, craft a TAR with a symlink `"tmp_link" -> "/tmp/sessions"`, then files `"tmp_link/{fake_username}/{predicted_sessionID}"` containing admin JSON. Extraction follows the symlink, writing to `/tmp/sessions/{fake_username}/{sessionID}`.

Tying it back: Use a fake username like `"noexist"` (not in DB, but Redis doesn't care). Failed login sets Redis for it. Predict 3 session IDs (timestamp ±1 for jitter). Upload TAR as a real user. Forge cookies with `username="noexist"` (session ignored), hit `/user/admin`—middleware pulls from Redis/file, sees admin role.

## Clear Methodology of the Attack

Now that we've audited and connected the dots, here's the step-by-step exploit:

### 1. Register and Login as a Legit User

- POST `/register` and `/login` with a clean username (e.g., `"victim"`) and password. This gets you cookies and upload access. Use JSON payloads as per source.

### 2. Set Redis for Fake User and Predict Session IDs

- POST `/login` with `username="noexist"`, wrong password. This sets Redis `"noexist" -> sessionID`.
- Grab `"Date"` header, parse to Unix timestamp (e.g., via Python's `datetime`).
- Compute `SHA256(str(timestamp-1))`, `SHA256(str(timestamp))`, `SHA256(str(timestamp+1))` for 3 possible IDs.

### 3. Craft and Upload Malicious TAR

- Create TAR: Symlink `"tmp_link" -> "/tmp/sessions"`.  (CVE 2024 0406)
- For each predicted ID, add file `"tmp_link/noexist/{ID}"` with `{"username":"noexist","id":1337,"role":"admin"}`.
- Upload to `/user/upload` as `"archive"` (multipart form).

### 4. Forge Cookies and Access Admin

- Set cookies: `username="noexist"`, `session="anything"`.
- GET `/user/admin`. Middleware uses Redis to find the ID, reads your forged file, grants admin.
- **Flag in response:** Look for `{{.FLAG}}` in HTML (e.g., `HTB{some_flag}`).
