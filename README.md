# ROUGE · Early Warning and Link Analysis

This local prototype collects public news through eight RSS feeds and the public GDELT DOC API. Optional X, Facebook Page, and linked Instagram professional-account connectors can be enabled with provider credentials in `.env`. The service stores canonical articles in SQLite, deduplicates repeat URLs, and builds incident alerts from recent stored items. The browser reads alerts from the backend; it does not fetch source feeds itself.

## Run from a clean Windows machine

1. Install Python 3.10 or later and obtain this project folder from your approved repository or project archive.
2. Open PowerShell in the project folder and confirm Python is available:

   ```powershell
   py -3 --version
   ```

3. Create and activate a local virtual environment. No third-party Python packages are required:

   ```powershell
   py -3 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```

4. Create the local configuration file:

   ```powershell
   Copy-Item .env.example .env
   ```

   The service reads `NSP_PORT` and `NSP_DB_PATH` from `.env`; both have usable defaults. SMTP and social-source credentials are optional. To configure social sources, paste the credentials described below into the matching empty entries. Keep `.env` local and never commit it.

5. Start the backend:

   ```powershell
   python early_warning_service.py
   ```

   It immediately fetches each configured RSS/GDELT source, logs the result and per-source item counts, then repeats every 12 minutes. Keep this terminal open.

6. Open `http://127.0.0.1:8765/` and submit the **Request access** form with the service number, official type, photo, passcode, and demo fingerprint scan. A supervisor can enter **Supervisor review mode** and use the **Access requests** page to accept or reject it. Only accepted accounts can sign in; supervisors can search a service number and cancel an active service. Other officials can select **Early warning** on the Home screen. A **Media official** is sent directly to a read-only status board that lists only news items whose latest recorded status is flagged, acknowledged, false alarm, or escalated.

For local prototype use, the sign-in form is prefilled with the seeded **demo supervisor** account: **Military intelligence**, service number `MZ-123`, passcode `12345678`. The demo fingerprint hold is still required. This public, hardcoded demo credential is not safe for deployment or real accounts; use synthetic data only.

The officer platform uses the supplied emerald HUD/target-eye artwork as a fixed, darkened page background; its SVG is served locally from `assets/platform-background.svg`. The ROUGE logo and the "System online" masthead are not displayed.

The active RSS feeds are Punch, Vanguard, Premium Times, Channels TV, Daily Trust, The Nation, Guardian Nigeria, and BBC Pidgin. A feed that returns an HTTP or parsing error is shown as **failing**, with its error; the service does not substitute synthetic articles for a particular failed source. If no connector is live, the prototype may show its conspicuously marked simulated fallback. Real alerts only appear when a working source returns incident-related content that can be classified and placed in the Nigerian gazetteer. Network access, source availability, and provider terms are outside the prototype's control.

## Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `NSP_PORT` | `8765` | Local HTTP port. |
| `NSP_DB_PATH` | `nsp_early_warning.sqlite3` in the project directory | SQLite file for fetched articles, saved workspace records, link-analysis data, and append-only audit events. Relative paths are resolved from the project directory. |
| `NSP_SMTP_HOST` | empty | SMTP server used to deliver family email verification codes. |
| `NSP_SMTP_PORT` | `587` | SMTP server port. |
| `NSP_SMTP_USERNAME` / `NSP_SMTP_PASSWORD` | empty | Optional SMTP authentication credentials. |
| `NSP_SMTP_FROM` | SMTP username, or empty | Sender address for verification emails. |
| `NSP_SMTP_USE_SSL` | `false` | Connect using implicit TLS. |
| `NSP_SMTP_USE_STARTTLS` | `true` | Upgrade an SMTP connection using STARTTLS. |
| `NSP_X_BEARER_TOKEN` | empty | X API bearer token. Enables recent public-post searches for Nigeria-related threat and violence terms. |
| `NSP_META_PAGE_ACCESS_TOKEN` | empty | Meta Page access token. Enables posts from that authorized Facebook Page and media from its linked Instagram professional account, if available to the token. |

Citizen records created in the app, notes, case links, access requests, approved official accounts, and audit activity are saved to this local SQLite database. Official passcodes are stored as salted PBKDF2 hashes; the submitted profile photo is retained for supervisor review. Keep using the same database file to return to the same records. This prototype stores synthetic data only; back up the database file if you need to preserve it when moving the project.

## Case management and family reporting

Police and Military Intelligence officials can open the active **Case management** tool from Home. They can review family reports, create and manage cases, record sightings and append-only notes, set priorities and assignments, and send simulated area alerts that require acknowledgement. Immigration officials see only active border-watch alert summaries; Correctional Service remains unavailable.

Families can use the separate public portal at `http://127.0.0.1:8765/family-report`. A report stays **New / unverified** until an authorised officer reviews it. Reporters must verify their email before submitting. The portal displays a private status-check token once after submission; keep it with the report reference. The status lookup accepts the token in a POST body and returns status updates only—not case details, contact information, photos, officer notes, or the face gallery.

Email verification uses the configured SMTP server. Set `NSP_SMTP_HOST`, `NSP_SMTP_PORT`, `NSP_SMTP_USERNAME`, `NSP_SMTP_PASSWORD`, and `NSP_SMTP_FROM` in the local `.env`; optionally set `NSP_SMTP_USE_SSL` and `NSP_SMTP_USE_STARTTLS` to match the provider. `.env.example` contains empty credential placeholders only. Until SMTP is configured and reachable, verification fails explicitly and family reports cannot be submitted. Never commit `.env` or use real personal/security data in this prototype.

Citizen search asks for one lookup method at a time: a name, NIN, or picture. A case reference is requested only when a case-specific action needs one.

To enable X, create an X developer project/app with API access to recent search, copy its **Bearer Token**, and paste it after `NSP_X_BEARER_TOKEN=` in `.env`. X access, usage limits, and possible pay-per-use charges depend on the current developer plan; check the X developer dashboard before enabling it. The connector searches the recent-post endpoint every 12 minutes for a fixed set of Nigeria and threat/violence terms; it does not search historical posts.

To enable Meta sources, create/configure a Meta developer app and obtain a **Page access token** for a Facebook Page you are authorized to monitor. Paste it after `NSP_META_PAGE_ACCESS_TOKEN=`. The Facebook connector reads published items from that Page's feed. The Instagram connector additionally reads media only when the Page is linked to an Instagram professional account and the token/app has the required permissions (including `pages_show_list`, `pages_read_engagement`, and `instagram_basic`, subject to Meta review and account eligibility). These APIs do not provide unrestricted keyword search over all Facebook or Instagram posts. A token without the required account access or permissions will show an explicit failing source status.

After adding or changing credentials, restart `early_warning_service.py`; configured sources are fetched automatically, and their health appears in the source-status checklist. Do not paste credentials into chat, source code, or a committed file. If no approved credentials are configured, the public RSS/GDELT sources continue to work as before.

## Source and safety limits

Only public RSS/GDELT data and API content permitted by the credentials are fetched. The service does not scrape websites or collect social account handles or profile photos. Social posts are unverified leads, not confirmed incidents; social-only alerts are labelled accordingly, and High-confidence alerts still require analyst review. Source outages are reported instead of being masked. The pipeline performs language estimation, Nigerian state/LGA extraction, event classification, content-level duplicate clustering, confidence scoring, and human review gating for High-confidence alerts.

The gazetteer contains 37 state/FCT entries and 774 LGA names. It is the MIT-licensed `lgas.json` dataset from [temikeezy/nigeria-geojson-data](https://github.com/temikeezy/nigeria-geojson-data), pinned to commit `3cd13e6088bf72b0873d7d6fa7cf4cf0294ad9a6`; the accompanying license is in `data/LICENSE-nigeria-geojson-data.txt`. It is not an official government boundary certification and should be verified against an authorised reference before operational use.

**Prototype security boundary:** the HTTP service binds to loopback. Its supervisor review checkbox and `X-NSP-Supervisor` demo header are not authentication or production authorization. The fingerprint scan is simulated and does not capture or verify a biometric template. Do not expose the service to a network or use real credentials, biometrics, citizen, or security data. Production requires server-side identity and role enforcement, TLS, managed secrets, reviewed source licences, durable immutable auditing, and operational analyst controls.

## Link analysis prototype

After signing in as a **Police officer** or **Military intelligence** official, select **Link analysis** from the Home tools. Immigration and correctional service roles see the tool disabled. Enter a synthetic NIN; the first lookup requires a case reference and a reason. Add up to 10 people by dragging the circle onto the board or focusing it and pressing Enter. Select **Check links** to run the relationship check and show its evidence over a Leaflet/Esri Nigeria context map, with Esri and OpenStreetMap attribution. The relationship nodes are illustrative and are not positioned at anyone's location; no location data is used or displayed by this map. The user does not choose a link type.

Location analysis remains a separate, explicitly requested workflow requiring a legal authorization reference, case, reason, authorized start/end dates, and supervisor-mode demo approval. A different service number must approve the request; approval expires after 24 hours. Only then can the tool analyze the invented location fixtures inside the authorized period. The location connector remains **not configured** and does not access phone or telecom data. Leaflet and Esri basemap tiles are requested from their public services for the context and approved synthetic location maps; if unavailable, a marked fallback is shown. Do not use this prototype to track or locate real people.

Board saves and location requests are stored in the local SQLite database alongside append-only audit events. The supervisor-mode checkbox and `X-NSP-Supervisor` header are demonstration controls only: this application does not authenticate roles or provide a real approval boundary. Do not deploy it for operational use or enter real citizen or location data. A production version needs server-side permissions, a secured location-data connector for lawfully obtained records, an auditable approval service, and a graph database (for example, Neo4j) for relationship queries. Family and location matches are statistical leads; measure false matches and communicate confidence honestly.

## Number plate video search

Police and Military Intelligence demo accounts can open **Number plate reader** from the Home tools. Choose a video file, enter a plate number and the footage location, then select **Find plate**. The location is displayed as supplied by the user; it is not read from or verified against the footage. The backend samples up to four frames per second, reports progress, and returns up to five exact normalized OCR-text matches with timestamps and still frames. Spaces and hyphens in the entered plate are ignored. Uploaded video is written to a temporary file and deleted when processing finishes; search jobs and frames are held in memory for up to one hour and are not persisted to the database.

Supported extensions are MP4, MOV, AVI, MKV, MPEG, WebM, and Hikvision DAV/H.264 (the latter formats only when the installed OpenCV video backend can decode them), up to 200 MB per upload, two hours per video, and 16 megapixels per frame. Install the optional Python packages with `pip install -r requirements-vf.txt`; install the separate Tesseract OCR engine as well (on Windows, for example, `winget install --id UB-Mannheim.TesseractOCR --exact`). If Tesseract is missing, the UI reports that requirement and does not start a search. The service uses OpenCV to decode videos and Tesseract for OCR. When full-frame and cascade OCR do not find the requested text, it also checks overlapping full-resolution image tiles and retries those tiles at double size to improve reads of small plates. It does not include a plate-detection model trained for Nigerian plates; OCR and OpenCV's bundled Russian-plate cascade are heuristics, so distant, moving, angled, blurred, obscured or poorly lit plates may be missed or misread. The OCR score is not a calibrated probability. Test with authorized sample footage and verify every result against the original video.

This feature searches uploaded recordings only. It does not yet connect to live Hikvision/RTSP cameras or configure camera credentials. The local prototype's demo role checks are not a production security boundary; do not expose this service to a network or use it for operational decisions.

## AI Visual Forensics

Signed-in **Police officer** and **Military intelligence** officials open the workspace from Home → **AI Visual Forensics** (also in the sidebar). Other roles see the tool disabled. The module is implemented as a modular router (`vf_routes.py`) over the same Handler and session model as every other ROUGE API route, with the analysis pipeline in `vf_image.py` and the UI in `vf.js`.

Workflow:

1. **Image intake** — drag-and-drop or browse. JPEG/JPG, PNG, WebP and TIFF are accepted up to 24 MB and 6 files per upload. Each original is SHA-256 hashed and written **immutably** to `data/vf_evidence/<sha256>.bin` (read-only); duplicate uploads collapse to the same evidence asset. Corrupted or unsupported files return a clear per-file error without aborting the batch.
2. **Viewer** — zoom (buttons and mouse wheel), pan/drag, fit-to-screen, reset, full-screen, region selection (hold **Shift** and drag), and a magnified crop. Overlay boxes and annotations are stored in **original image pixel coordinates** and repositioned as the viewer zooms or resizes. Toggles hide AI findings or annotations.
3. **Findings** — the full-analysis run produces structured findings, each with a unique ID, category, neutral description, bounding box, method/model, confidence (or an explicit "no calibrated confidence" label), limitations, alternative explanations, review status and timestamp. Review statuses are **New / Pending review / Confirmed observation / Inconclusive / Rejected**. "Confirmed observation" means a human verified the stated visual feature; it never means an AI hypothesis is proven. Confirming, rejecting or marking inconclusive requires a note recording the reason.
4. **Eye, gaze & reflection examination** — detects faces/eye regions and estimates apparent gaze direction as a clearly-labelled **heuristic** (not a measurement of attention or intent), flags occlusion/blur/low resolution, and surfaces candidate corneal highlights for **manual** inspection. Reflected structures are never identified from the evidence.
5. **Shadow & lighting** — grid luminance statistics, an illumination map, apparent light direction, glare/uneven-illumination flags. These are prompts for manual review, explicitly not manipulation verdicts.
6. **Image clarity engine** — denoise, sharpen, brightness/contrast, shadow/highlight, gamma and upscaling. Enhanced copies are stored **separately** as derivatives with their own SHA-256 and recorded settings; the original evidence is never modified. Sharpening is stated not to reverse blur or recover lost information.
7. **Comparison workspace** — side-by-side view, per-image metadata and EXIF diffs, dimensions and hashes. Visual similarity is stated not to prove that two images depict the same event, person or location; no individual identification is performed.
8. **Investigation report** — case reference, analyst/reviewer, original file details and SHA-256, analysis history, AI findings vs. human-verified observations, enhancement operations, uncertainties, limitations statement and reviewer notes. Export as **JSON + CSV**; the preview opens a print-to-PDF view. The report makes no legal-admissibility or chain-of-custody claim.

### Optional dependencies and capabilities

The base service needs no third-party packages. Visual Forensics uses Pillow and numpy for real analysis; OpenCV enables real face/eye detection, and Tesseract enables OCR. Install the optional set with `pip install -r requirements-vf.txt`. When a capability is unavailable the module reports it as **unsupported** instead of fabricating output — this is by design. Face/eye cascades are vendored under `data/vf_models/` (provenance and licensing in that folder's README). AI super-resolution (Real-ESRGAN) is intentionally **not** installed by default; the clarity engine offers Lanczos resampling and states that resampling does not recover information that was never captured.

### Safety and evidentiary boundaries

Every detector output is labelled `AI MODEL` or `PROCESSING`; only human-verified items can be `Confirmed observation`. The tool does not infer criminality, hostile intent, identity or guilt from appearance, does not perform facial recognition or identity matching, does not treat missing metadata as evidence of tampering, and does not treat metadata timestamps as proof of when or where a photo was taken. Enhanced or reconstructed pixels never replace original pixels in the evidence record. The same prototype security boundary described above applies: this is not production-grade authorization, and synthetic data only.
