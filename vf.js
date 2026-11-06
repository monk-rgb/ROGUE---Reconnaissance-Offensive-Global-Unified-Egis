// Visual Forensics — AI-assisted image investigation workspace.
// Injected into the ROUGE index.html shell: state merges into `state.vf`,
// and renderVisualForensics() is called by index.html like the other tool pages.
"use strict";

function vfSetup() {
  if (!state.vf) {
    state.vf = {
      images: [], selectedId: null, loading: false, error: "", analysed: {},
      findings: [], annotations: [], derivatives: [],
      viewer: { zoom: 1, panX: 0, panY: 0, fit: true, region: null, dragging: false },
      showFindings: true, showAnnotations: true, enhancement: null,
      compareIds: [], compareData: null, compareSync: { zoom: 1, panX: 0, panY: 0 },
      reportPreview: null, selectedFindingId: null, eyePanelOpen: false,
      magnifier: null, brightnessMap: null, mode: null, caseRef: null,
    };
  }
  if (state.vf.caseRef === undefined) state.vf.caseRef = null;
  return state.vf;
}

function vfImage() { return vfSetup().images.find(img => img.id === state.vf.selectedId) || null; }

// The original image is served by an authenticated GET. A plain <img src> cannot send
// the Authorization header, so the session token is appended as a query parameter.
function vfImageUrl(imageId) {
  const token = state.authToken ? `?token=${encodeURIComponent(state.authToken)}` : "";
  return `/api/vf/image/${encodeURIComponent(imageId)}${token}`;
}

async function vfLoadImages() {
  const vf = vfSetup();
  vf.loading = true; vf.error = "";
  try {
    const data = await apiRequest("/api/vf/images");
    vf.images = data.images || [];
    if (!vf.selectedId && vf.images.length) vf.selectedId = vf.images[0].id;
    if (vf.selectedId && !vf.images.some(img => img.id === vf.selectedId)) {
      vf.selectedId = vf.images.length ? vf.images[0].id : null;
    }
  } catch (error) { vf.error = error.message; }
  vf.loading = false;
  if (state.page === "visual-forensics") renderVisualForensics(document.getElementById("page-content"));
}

async function vfLoadImageData(imageId, { keepView = false } = {}) {
  const vf = vfSetup();
  try {
    const [findingsData, annotationsData, derivativesData] = await Promise.all([
      apiRequest(`/api/vf/findings/${imageId}`),
      apiRequest(`/api/vf/annotations/${imageId}`),
      apiRequest(`/api/vf/derivatives/${imageId}`),
    ]);
    vf.findings = findingsData.findings || [];
    vf.annotations = annotationsData.annotations || [];
    vf.derivatives = derivativesData.derivatives || [];
  } catch (error) {
    // The viewer keeps showing the original; only the side data is missing.
    toast(`Could not load image data: ${error.message}`, true);
    throw error;
  }
  const imageChanged = vf.selectedId !== imageId;
  if (!keepView || imageChanged) {
    vf.selectedId = imageId;
    Object.assign(vf.viewer, { zoom: 1, panX: 0, panY: 0, fit: true, region: null });
  }
  vf.enhancement = null;
  renderVisualForensics(document.getElementById("page-content"));
}

function vfSelectImage(imageId) {
  const vf = vfSetup();
  const changed = vf.selectedId !== imageId;
  vf.selectedId = imageId;
  vf.selectedFindingId = null; vf.eyePanelOpen = false;
  if (changed) {
    // Swap the picture in place so it is visible immediately, then pull its data.
    vf.findings = []; vf.annotations = []; vf.derivatives = []; vf.enhancement = null;
    document.querySelectorAll("[data-vf-select]").forEach(node =>
      node.closest(".vf-image-card")?.classList.toggle("selected", node.dataset.vfSelect === imageId));
    vfSetImage(imageId);
    renderVisualForensics(document.getElementById("page-content"));
  }
  vfLoadImageData(imageId);
}

async function vfDeleteImage(imageId) {
  const vf = vfSetup();
  const image = vf.images.find(img => img.id === imageId);
  const label = image ? image.filename : imageId;
  if (!confirm(`Remove "${label}" from the Visual Forensics workspace?\n\nThis deletes the workspace record and its findings, annotations and processed copies. The immutable evidence original remains on disk.`)) return;
  try {
    await apiRequest(`/api/vf/image/${encodeURIComponent(imageId)}/delete`, {
      method: "POST", body: JSON.stringify({ reason: "Analyst removed image from workspace" }),
    });
  } catch (error) { toast(`Could not remove image: ${error.message}`, true); return; }
  vf.images = vf.images.filter(img => img.id !== imageId);
  if (vf.selectedId === imageId) {
    vf.selectedId = vf.images.length ? vf.images[0].id : null;
    vf.findings = []; vf.annotations = []; vf.derivatives = []; vf.enhancement = null;
  }
  toast(`Removed ${label} from the workspace.`);
  if (vf.selectedId) await vfLoadImageData(vf.selectedId);
  else renderVisualForensics(document.getElementById("page-content"));
}

async function vfAnalyse(imageId) {
  const vf = vfSetup();
  const button = document.querySelector(`[data-vf-analyse="${imageId}"]`);
  if (button) { button.disabled = true; button.textContent = "Analysing…"; }
  try {
    const result = await apiRequest(`/api/vf/analyse/${imageId}`, {
      method: "POST", body: JSON.stringify({ reason: "Full visual forensics analysis run" }),
    });
    vf.analysed[imageId] = result;
    toast(`Analysis complete: ${result.findings.length} finding(s).`);
    await vfLoadImageData(imageId, { keepView: true });
  } catch (error) {
    toast(`Analysis failed: ${error.message}`, true);
    if (button) { button.disabled = false; button.textContent = "Run full analysis"; }
  }
}

// ---------------------------------------------------------------------------
// Upload
// ---------------------------------------------------------------------------

async function vfUploadFiles(fileList) {
  const vf = vfSetup();
  let files = Array.from(fileList || []);
  if (!files.length) return;
  const maxBytes = 24 * 1024 * 1024;
  // One picture at a time: a drop/picker selection of several files is rejected outright
  // rather than silently truncated, so the analyst always knows what was analysed.
  if (files.length > 1) {
    toast("Only one picture can be analysed at a time. Select a single image.", true);
    return;
  }
  const file = files[0];
  if (!/image\/(jpeg|jpg|png|webp|tiff)/i.test(file.type) && !/\.(jpe?g|png|webp|tiff?)$/i.test(file.name)) {
    toast(`${file.name}: unsupported file type. JPEG, PNG, WebP and TIFF are accepted.`, true); return;
  }
  if (file.size > maxBytes) { toast(`${file.name}: exceeds the 24 MB limit.`, true); return; }
  const form = new FormData();
  form.append("files", file, file.name);
  const caseRef = document.getElementById("vf-case-ref")?.value.trim();
  form.append("caseRef", caseRef || "—");
  vf.loading = true;
  renderVisualForensics(document.getElementById("page-content"));
  vfShowLoadingRow("Uploading " + file.name + " — hashing and storing the original…");
  try {
    const response = await fetch("/api/vf/upload", {
      method: "POST", body: form,
      headers: {
        "X-NSP-Official": state.official?.service || "UNKNOWN",
        "X-NSP-Official-Type": state.official?.type || "",
        ...(state.authToken ? { Authorization: `Bearer ${state.authToken}` } : {}),
        ...(state.official?.supervisor ? { "X-NSP-Supervisor": "demo" } : {}),
      },
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(body.error || `Upload failed (${response.status}).`);
    (body.errors || []).forEach(message => toast(message, true));
    if (body.images?.length) {
      toast(`Uploaded ${body.images.length} image(s); originals stored immutably by SHA-256.`);
      // Put the new record at the top of the local list, select it and paint it in the
      // viewer straight away. Everything below in this function is only enrichment
      // (findings/annotations/derivatives) — a failure there must not hide the image.
      const known = new Set(vf.images.map(img => img.id));
      const added = body.images.filter(img => !known.has(img.id));
      vf.images = [...added, ...vf.images];
      vf.selectedId = body.images[0].id;
      vf.findings = []; vf.annotations = []; vf.derivatives = [];
      vf.enhancement = null; vf.selectedFindingId = null; vf.eyePanelOpen = false;
      Object.assign(vf.viewer, { zoom: 1, panX: 0, panY: 0, fit: true, region: null });
      vf.loading = false;
      vf.error = "";
      renderVisualForensics(document.getElementById("page-content"));
      try {
        await vfLoadImageData(vf.selectedId);
      } catch (error) {
        toast(`Image is loaded, but its findings could not be fetched: ${error.message}`, true);
      }
      return;
    }
  } catch (error) { toast(`Upload failed: ${error.message}`, true); }
  vf.loading = false;
  await vfLoadImages();
}

// Shows progress inside the (persistent) viewer placeholder while a render is pending.
function vfShowLoadingRow(text) {
  const row = document.getElementById("vf-loading-row");
  if (!row) return;
  row.textContent = text;
  row.classList.remove("hidden");
}

// ---------------------------------------------------------------------------
// Viewer helpers (zoom/pan/region are applied to an <img> inside a viewport)
// ---------------------------------------------------------------------------

// The stage is transformed with translate() then scale() from a 0 0 origin, which
// CSS applies as translate * scale. So panX/panY are in viewport pixels and the
// displayed width of the image is naturalWidth * zoom at every zoom level.
function vfFitNatural() {
  const vf = vfSetup();
  const viewport = document.querySelector(".vf-viewport");
  const image = document.querySelector(".vf-stage-img");
  if (!viewport || !image) return;
  const naturalWidth = image.naturalWidth || vfImage()?.width || 0;
  const naturalHeight = image.naturalHeight || vfImage()?.height || 0;
  if (!naturalWidth || !naturalHeight) return;
  const box = viewport.getBoundingClientRect();
  const width = box.width || viewport.clientWidth;
  const height = box.height || viewport.clientHeight;
  if (!width || !height) return;
  const scale = Math.min(width / naturalWidth, height / naturalHeight, 1);
  vf.viewer.zoom = scale;
  vf.viewer.panX = (width - naturalWidth * scale) / 2;
  vf.viewer.panY = (height - naturalHeight * scale) / 2;
  vf.viewer.fit = true;
  vfApplyViewerTransform();
}

function vfApplyViewerTransform() {
  const vf = vfSetup();
  const stage = document.querySelector(".vf-image-stage");
  if (!stage) return;
  const { zoom, panX, panY } = vf.viewer;
  stage.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
  const label = document.getElementById("vf-zoom-label");
  if (label) label.textContent = `${Math.round(zoom * 100)}%`;
  document.querySelectorAll(".vf-overlay-box").forEach(node => {
    const box = JSON.parse(node.dataset.box || "[0,0,0,0]");
    node.style.left = `${box[0] * zoom}px`;
    node.style.top = `${box[1] * zoom}px`;
    node.style.width = `${box[2] * zoom}px`;
    node.style.height = `${box[3] * zoom}px`;
  });
}

function vfSetImage(imageId) {
  const vf = vfSetup();
  const image = vf.images.find(img => img.id === imageId);
  const stageImage = document.querySelector(".vf-stage-img");
  if (!image || !stageImage) return;
  Object.assign(vf.viewer, { zoom: 1, panX: 0, panY: 0, fit: true, region: null });
  vfApplyViewerTransform();
  const onReady = () => vfFitNatural();
  stageImage.src = vfImageUrl(image.id);
  if (stageImage.complete && stageImage.naturalWidth) onReady();
  else stageImage.addEventListener("load", onReady, { once: true });
}

function vfZoomBy(factor, centerX, centerY) {
  const vf = vfSetup();
  const viewport = document.querySelector(".vf-viewport");
  if (!viewport) return;
  const box = viewport.getBoundingClientRect();
  const cx = centerX ?? box.width / 2;
  const cy = centerY ?? box.height / 2;
  const current = vf.viewer.zoom > 0 ? vf.viewer.zoom : 1;
  const next = Math.min(16, Math.max(0.05, current * factor));
  if (next === current) return;
  const ratio = next / current;
  vf.viewer.panX = cx - (cx - vf.viewer.panX) * ratio;
  vf.viewer.panY = cy - (cy - vf.viewer.panY) * ratio;
  vf.viewer.zoom = next;
  vf.viewer.fit = false;
  vfApplyViewerTransform();
}

function vfJumpToBox(box) {
  const vf = vfSetup();
  const viewport = document.querySelector(".vf-viewport");
  const image = vfImage();
  const stage = document.querySelector(".vf-image-stage");
  if (!viewport || !image || !stage || !image.width) return;
  const boxWidth = viewport.getBoundingClientRect().width;
  const zoom = Math.min(6, Math.max(0.4, (boxWidth * 0.7) / Math.max(24, box[2])));
  vf.viewer.zoom = zoom;
  vf.viewer.panX = boxWidth / 2 - (box[0] + box[2] / 2) * zoom;
  vf.viewer.panY = viewport.getBoundingClientRect().height / 2 - (box[1] + box[3] / 2) * zoom;
  vf.viewer.fit = false;
  vfApplyViewerTransform();
  stage.scrollIntoView({ block: "nearest" });
}

function vfMagnifyBox(box, title, source) {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return;
  const viewport = document.querySelector(".vf-viewport");
  if (!viewport) return;
  const node = document.createElement("div");
  node.className = "vf-magnifier";
  node.innerHTML = `
    <div class="vf-magnifier-head"><strong>${esc(title)}</strong><span class="eyebrow">${esc(source)}</span>
      <button class="btn small secondary" data-vf-magnify-close>Close</button></div>
    <div class="vf-magnifier-body">
      <img src="${vfImageUrl(image.id)}" style="image-rendering: pixelated;
        transform: translate(${-(box[0])}px, ${-(box[1])}px) scale(${Math.min(8, 240 / Math.max(24, Math.min(box[2], box[3])))});">
      <div class="vf-magnifier-meta">
        <div>Box: ${box.map(n => Math.round(n)).join(", ")} · coordinates are in original image pixels.</div>
        <div class="eyebrow">This crop is a magnified view of ORIGINAL pixels. Nothing has been generated or reconstructed.</div>
      </div>
    </div>`;
  node.querySelector("[data-vf-magnify-close]").addEventListener("click", () => node.remove());
  viewport.appendChild(node);
}

// ---------------------------------------------------------------------------
// Finding actions
// ---------------------------------------------------------------------------

async function vfFindingReview(findingId, status, note) {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return;
  try {
    await apiRequest(`/api/vf/findings/${image.id}/${findingId}/review`, {
      method: "POST",
      body: JSON.stringify({ reviewStatus: status, note, caseRef: image.caseRef }),
    });
    toast(`Finding ${findingId} → ${status}`);
    await vfLoadImageData(image.id, { keepView: true });
  } catch (error) { toast(error.message, true); }
}

async function vfFindingNote(findingId, note) {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return;
  try {
    await apiRequest(`/api/vf/findings/${image.id}/${findingId}/note`, {
      method: "POST", body: JSON.stringify({ note, caseRef: image.caseRef }),
    });
    toast("Note added to finding.");
    await vfLoadImageData(image.id, { keepView: true });
  } catch (error) { toast(error.message, true); }
}

async function vfAddAnnotation(box, label, note) {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return;
  try {
    await apiRequest(`/api/vf/annotations/add/${image.id}`, {
      method: "POST",
      body: JSON.stringify({ box: box.map(Math.round), label, note, kind: "manual", caseRef: image.caseRef }),
    });
    toast("Annotation saved.");
    await vfLoadImageData(image.id, { keepView: true });
  } catch (error) { toast(error.message, true); }
}

// ---------------------------------------------------------------------------
// Enhancement
// ---------------------------------------------------------------------------

async function vfApplyEnhancement() {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return;
  const read = (id, fallback) => parseFloat(document.getElementById(id)?.value ?? fallback) || fallback;
  const settings = {
    denoise: read("vf-set-denoise", 0), sharpen: read("vf-set-sharpen", 0),
    brightness: read("vf-set-brightness", 0), contrast: read("vf-set-contrast", 0),
    shadows: read("vf-set-shadows", 0), highlights: read("vf-set-highlights", 0),
    gamma: read("vf-set-gamma", 1), upscale: read("vf-set-upscale", 1),
  };
  const button = document.getElementById("vf-enhance-run");
  if (button) { button.disabled = true; button.textContent = "Processing…"; }
  try {
    const result = await apiRequest(`/api/vf/enhance/${image.id}`, {
      method: "POST",
      body: JSON.stringify({ settings, reason: "Clarity enhancement applied" }),
    });
    vf.enhancement = result;
    toast("Enhanced copy stored separately (processed SHA-256 recorded).");
  } catch (error) { toast(error.message, true); }
  renderVisualForensics(document.getElementById("page-content"));
}

function vfExportDerivative(derivative) {
  const link = document.createElement("a");
  link.href = `/api/vf/derivatives/${derivative.imageId}/serve/${derivative.id}`;
  link.download = `processed_${derivative.id}.png`;
  link.click();
}

// ---------------------------------------------------------------------------
// Comparison + report
// ---------------------------------------------------------------------------

async function vfRunComparison() {
  const vf = vfSetup();
  const selected = vf.images.filter(img => vf.compareIds.includes(img.id));
  if (selected.length < 2) return toast("Select at least two images to compare.", true);
  try {
    const data = await apiRequest("/api/vf/compare", {
      method: "POST",
      body: JSON.stringify({ imageIds: vf.compareIds, reason: "Side-by-side comparison" }),
    });
    vf.compareData = data;
    renderVisualForensics(document.getElementById("page-content"));
  } catch (error) { toast(error.message, true); }
}

async function vfGenerateReport() {
  const vf = vfSetup();
  const ids = vf.compareIds.length ? vf.compareIds : (vf.selectedId ? [vf.selectedId] : []);
  if (!ids.length) return toast("Select at least one image for the report.", true);
  const reviewer = document.getElementById("vf-report-reviewer")?.value.trim() || "";
  const reviewerNotes = document.getElementById("vf-report-notes")?.value.trim() || "";
  try {
    const data = await apiRequest("/api/vf/report", {
      method: "POST",
      body: JSON.stringify({ imageIds: ids, reviewer, reviewerNotes, caseRef: vfImage()?.caseRef || "—" }),
    });
    vf.reportPreview = data.report;
    renderVisualForensics(document.getElementById("page-content"));
    vfDownloadReport();
  } catch (error) { toast(error.message, true); }
}

function vfDownloadReport() {
  const vf = vfSetup();
  if (!vf.reportPreview) return;
  const report = vf.reportPreview;
  const jsonBlob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const jsonLink = document.createElement("a");
  jsonLink.href = URL.createObjectURL(jsonBlob);
  jsonLink.download = `${report.reportId}.json`;
  jsonLink.click();
  // CSV export of structured findings
  const rows = ["finding_id,image_id,category,title,review_status,source,confidence,method"];
  report.sections.forEach(section => section.findings.forEach(finding => rows.push([
    finding.id, finding.imageId, finding.category, `"${finding.title.replace(/"/g, '""')}"`,
    finding.reviewStatus, finding.source,
    finding.confidence ?? "", `"${finding.method.replace(/"/g, '""')}"`,
  ].join(","))));
  const csvBlob = new Blob([rows.join("\n")], { type: "text/csv" });
  const csvLink = document.createElement("a");
  csvLink.href = URL.createObjectURL(csvBlob);
  csvLink.download = `${report.reportId}_findings.csv`;
  csvLink.click();
  toast(`Report ${report.reportId} exported (JSON + CSV). Use your PDF viewer to print-to-PDF from the preview.`);
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function vfFindingBadge(finding) {
  const statusColors = {
    "New": "var(--olive)", "Pending review": "var(--amber)",
    "Confirmed observation": "var(--green)", "Inconclusive": "var(--line)", "Rejected": "var(--red)",
  };
  return `<span class="vf-badge" style="border-color:${statusColors[finding.reviewStatus] || "var(--line)"}">
    ${esc(finding.reviewStatus)}</span>
    <span class="vf-badge">${esc(finding.source === "model" ? "AI MODEL" : finding.source === "manual" ? "MANUAL" : "PROCESSING")}</span>`;
}

function vfConfidenceLine(finding) {
  return `<div class="vf-finding-meta">
    <span class="eyebrow">METHOD</span> ${esc(finding.method || "—")}<br>
    <span class="eyebrow">CONFIDENCE</span> ${esc(finding.confidenceLabel || "n/a")}<br>
    <span class="eyebrow">LIMITATIONS</span> <span class="amber">${esc(finding.limitations || "—")}</span>
  </div>`;
}

function vfPanelCase() {
  const linked = vfSetup().caseRef;
  return `<div class="vf-case-row">
    <label class="eyebrow" for="vf-case-ref">CASE REFERENCE</label>
    <input id="vf-case-ref" placeholder="MP-260101-ABC123 (optional)" maxlength="100" value="${esc(linked || "")}" ${linked ? "readonly" : ""}
      title="${linked ? "Linked from Case management. Open the case there to change it." : "Optional case reference recorded with the upload"}">
  </div>`;
}

function vfUploadPanel() {
  const vf = vfSetup();
  return `<div class="panel vf-upload-panel">
    <div class="panel-head"><h2>${vf.images.length ? "New image" : "1 · Image intake"}</h2><span class="eyebrow">JPEG · PNG · WEBP · TIFF · ≤24 MB</span></div>
    <div class="vf-upload-body">
      ${vfPanelCase()}
      <div class="vf-dropzone" id="vf-dropzone" tabindex="0" role="button" aria-label="Upload one image">
        <div class="vf-dropzone-icon">⇪</div>
        <div class="vf-dropzone-text"><strong>Drag &amp; drop one picture here</strong> or click to browse</div>
        <div class="eyebrow vf-dropzone-note">One picture at a time · hashed (SHA-256) and stored immutably</div>
      </div>
      <input type="file" id="vf-file-input" accept="image/jpeg,image/png,image/webp,image/tiff,.jpg,.jpeg,.png,.webp,.tif,.tiff" hidden>
      <div id="vf-loading-row" class="vf-loading-row hidden" role="status"></div>
      ${vf.images.length ? `
        <div class="vf-intake-head"><span class="eyebrow">Recent pictures — click one to view it (all shown because they were analysed earlier)</span></div>
        <div class="vf-image-list">
        ${vf.images.map(img => `
          <div class="vf-image-card ${img.id === vf.selectedId ? "selected" : ""}">
            <button class="vf-image-card-open" data-vf-select="${img.id}" title="Open in viewer">
              <img src="${vfImageUrl(img.id)}" alt="${esc(img.filename)}" loading="lazy">
              <div class="vf-filename" title="${esc(img.filename)}">${esc(img.filename)}</div>
            </button>
            <button class="vf-image-remove" data-vf-remove="${img.id}" title="Remove this image">✕</button>
          </div>`).join("")}
        </div>` : ""}
    </div>
  </div>`;
}

function vfViewerPanel() {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) {
    // Keep this element in the page on every render: the upload progress row lives in it.
    return `<div class="panel vf-viewer-panel"><div class="panel-head"><h2>2 · Image viewer</h2></div>
      <div class="vf-empty-viewer">Upload a picture above and it will open here.</div></div>`;
  }
  const compareDerivative = vf.enhancement;
  return `<div class="panel vf-viewer-panel">
    <div class="panel-head"><h2>2 · Image viewer</h2><span class="eyebrow vf-viewer-name" title="${esc(image.filename)}">${esc(image.filename)}</span>
      <div class="vf-viewer-tools">
        <button class="btn small secondary vf-zoom-btn" data-vf-zoom="out" title="Zoom out" aria-label="Zoom out">−</button>
        <span id="vf-zoom-label" class="eyebrow vf-zoom-label">100%</span>
        <button class="btn small secondary vf-zoom-btn" data-vf-zoom="in" title="Zoom in" aria-label="Zoom in">+</button>
        <button class="btn small secondary" data-vf-fit>Fit</button>
        <button class="btn small secondary" data-vf-fullscreen>⛶</button>
        <label class="vf-toggle"><input type="checkbox" id="vf-toggle-findings" ${vf.showFindings ? "checked" : ""}> Findings</label>
        <label class="vf-toggle"><input type="checkbox" id="vf-toggle-annotations" ${vf.showAnnotations ? "checked" : ""}> Annotations</label>
        ${compareDerivative ? `<label class="vf-toggle"><input type="checkbox" id="vf-toggle-compare" checked> Original vs processed</label>` : ""}
      </div>
    <div class="vf-viewport" id="vf-viewport" data-vf-fullscreen-target>
      <div class="vf-image-stage" data-natural-width="${image.width}">
        <img class="vf-stage-img" src="${vfImageUrl(image.id)}" alt="${esc(image.filename)}" draggable="false">
        ${vf.showFindings ? vf.findings.filter(f => f.box[2] > 0 && f.box[3] > 0 && vf.showFindings).map(f => `
          <div class="vf-overlay-box vf-overlay-${esc(f.category)}" data-box="${esc(JSON.stringify(f.box))}"
               data-natural-width="${image.width}" title="${esc(f.title)}"></div>`).join("") : ""}
        ${vf.showAnnotations ? vf.annotations.map(ann => `
          <div class="vf-overlay-box vf-overlay-annotation" data-box="${esc(JSON.stringify(ann.box))}"
               data-natural-width="${image.width}" title="${esc(ann.label)}"></div>`).join("") : ""}
        ${vf.viewer.region ? `<div class="vf-region-box" data-region="1"
            style="left:${vf.viewer.region.left}px;top:${vf.viewer.region.top}px;
            width:${vf.viewer.region.width}px;height:${vf.viewer.region.height}px;"></div>` : ""}
      </div>
      ${compareDerivative ? `<div class="vf-compare-slider" id="vf-compare-slider">
        <div class="vf-compare-handle" style="left:50%"></div>
        <div class="vf-compare-labels"><span class="eyebrow">ORIGINAL</span><span class="eyebrow amber">PROCESSED (settings recorded; not the evidence file)</span></div>
      </div>
      <div class="vf-compare-overlay" id="vf-compare-overlay" style="clip-path: inset(0 50% 0 0); background-image:url('${vfImageUrl(image.id)}')"></div>` : ""}
      <div class="vf-hint eyebrow">Wheel / + − = zoom · drag = pan · Shift+drag = region</div>
    </div>
    <div class="vf-image-details">
      <div class="vf-detail"><span class="eyebrow">DIMENSIONS</span>${image.width}×${image.height}</div>
      <div class="vf-detail"><span class="eyebrow">FORMAT</span>${esc(image.format)} · ${(image.byteSize / 1024).toFixed(0)} KB</div>
      <div class="vf-detail"><span class="eyebrow">CASE</span>${esc(image.caseRef || "—")}</div>
      <div class="vf-detail"><span class="eyebrow">UPLOADED</span>${esc(new Date(image.uploadedAt).toLocaleString())}</div>
      <div class="vf-detail vf-hash vf-detail-wide" title="SHA-256"><span class="eyebrow">SHA-256</span>${esc(image.sha256)}</div>
      ${image.quality ? `<div class="vf-detail"><span class="eyebrow">BRIGHTNESS</span>${esc(image.quality.brightness.label)} (${image.quality.brightness.value})</div>
      <div class="vf-detail"><span class="eyebrow">SHARPNESS</span>${esc(image.quality.sharpness.label)} (${image.quality.sharpness.value})</div>
      <div class="vf-detail"><span class="eyebrow">NOISE</span>${esc(image.quality.noise.label)} (${image.quality.noise.value})</div>
      <div class="vf-detail"><span class="eyebrow">CLIPPING</span>shadow ${image.quality.exposureClipping.shadowPercent}% · highlight ${image.quality.exposureClipping.highlightPercent}%</div>` : ""}
    </div>
    ${image.quality ? `<details class="vf-quality-details"><summary>Image-quality metrics & what they mean</summary>
      ${["brightness", "contrast", "sharpness", "noise"].map(key => `
        <div class="vf-metric"><strong>${esc(key[0].toUpperCase() + key.slice(1))}:</strong>
        ${esc(image.quality[key].label)} (${image.quality[key].value}) — ${esc(image.quality[key].explanation)}</div>`).join("")}
      <div class="vf-metric"><strong>Exposure clipping:</strong> ${esc(image.quality.exposureClipping.explanation)}</div>
      <div class="vf-metric amber">${esc(image.quality.note)}</div>
    </details>` : ""}
    ${image.metadataFlags?.observations?.length ? `<details><summary>Integrity observations</summary>
      ${image.metadataFlags.observations.map(o => `<div class="vf-metric"><strong>${esc(o.title)}</strong> — ${esc(o.description)}
        <span class="eyebrow">(${esc(o.confidenceLabel)})</span></div>`).join("")}
    </details>` : ""}
  </div>`;
}

function vfFindingsPanel() {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return "";
  const findings = vf.findings;
  return `<div class="panel vf-findings-panel">
    <div class="panel-head"><h2>3 · Findings${findings.length ? ` <span class="eyebrow">(${findings.length})</span>` : ""}</h2>
      <button class="btn" data-vf-analyse="${image.id}">${vf.analysed[image.id] || vf.findings.length ? "Re-run analysis" : "Run full analysis"}</button>
    </div>
    <p class="eyebrow">AI/PROCESSING findings are algorithmic interpretations — never confirmed forensic evidence. Only "Confirmed observation" items were verified by a human, and only for the stated visual feature.</p>
    ${findings.length ? findings.map(finding => `
      <div class="vf-finding ${finding.id === vf.selectedFindingId ? "selected" : ""}" data-finding-id="${esc(finding.id)}">
        <div class="vf-finding-head" data-vf-open-finding="${esc(finding.id)}">
          <div><strong>${esc(finding.title)}</strong></div>
          <div class="vf-badges">${vfFindingBadge(finding)}</div>
        <div class="vf-finding-body" style="display:${finding.id === vf.selectedFindingId ? "block" : "none"}">
          <p>${esc(finding.description)}</p>
          ${vfConfidenceLine(finding)}
          <div class="vf-finding-actions">
            ${finding.box[2] > 0 ? `<button class="btn small" data-vf-jump="${esc(finding.id)}">Jump to region</button>
            <button class="btn small secondary" data-vf-magnify="${esc(finding.id)}">Magnified crop</button>` : ""}
            ${finding.category !== "capability" ? `
            <button class="btn small" data-vf-confirm="${esc(finding.id)}">Confirm observation</button>
            <button class="btn small secondary" data-vf-reject="${esc(finding.id)}">Reject</button>
            <button class="btn small secondary" data-vf-inconclusive="${esc(finding.id)}">Inconclusive</button>` : ""}
          </div>
          <details class="vf-note-form"><summary>Add / correct note</summary>
            <textarea id="vf-note-${esc(finding.id)}" rows="2" maxlength="800"
              placeholder="Record what you verified, or correct the AI description…"></textarea>
            <div class="vf-note-actions">
              <button class="btn small" data-vf-note="${esc(finding.id)}">Save note</button>
              <button class="btn small secondary" data-vf-note-confirm="${esc(finding.id)}">Save note + confirm</button>
            </div>
          </details>
          ${finding.analystNotes.length ? `<div class="vf-notes">
            ${finding.analystNotes.map(note => `<div class="vf-note"><strong>${esc(note.by)}</strong>
              <span class="eyebrow">${esc(new Date(note.at).toLocaleString())} · ${esc(note.action)}</span><br>${esc(note.note)}</div>`).join("")}
          </div>` : ""}
        </div>
      </div>`).join("") : `<p class="eyebrow">No findings yet. Run the full analysis to generate them.</p>`}
  </div>`;
}

function vfEyePanel() {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return "";
  const analysed = vf.analysed[image.id];
  const eyeFaces = analysed?.eyes?.faces || [];
  const eyeFindings = vf.findings.filter(f => f.category === "eye");
  const capabilityFindings = vf.findings.filter(f => f.category === "capability");
  return `<div class="panel">
    <div class="panel-head"><h2>4 · Eye, gaze & reflection examination</h2>
      <button class="btn small secondary" data-vf-eye-toggle>${vf.eyePanelOpen ? "Hide" : "Show"}</button></div>
    ${vf.eyePanelOpen ? `
      <p class="eyebrow">Apparent gaze direction is a heuristic estimate relative to the image, not a measurement of attention or intent. Unavailable capability is reported as unsupported, never simulated.</p>
      ${eyeFaces.length ? eyeFaces.map((face, index) => `
        <div class="vf-eye-face">
          <div class="vf-eye-face-head"><strong>Face ${index + 1}</strong>
            <span class="eyebrow">box ${face.faceBox.join(", ")}</span></div>
          ${face.eyes.map(eye => `
            <div class="vf-eye">
              <div class="vf-eye-crop" style="background-image:url('${vfImageUrl(image.id)}');
                background-size:${Math.min(1600, image.width * 8)}px;
                background-position:${-Math.min(0, eye.box[0] * 8 - (160 - eye.box[2] * 8) / 2)}px ${-eye.box[1] * 8}px;"></div>
              <div class="vf-eye-meta">
                <div><span class="eyebrow">APPARENT GAZE</span> ${esc(eye.gaze.direction)}
                  <span class="vf-badge">heuristic ${eye.gaze.confidence}</span></div>
                <div class="amber vf-small">${esc(eye.gaze.reason)}</div>
                <div><span class="eyebrow">HIGHLIGHTS</span> ${eye.specularSpots.length ? `${eye.specularSpots.length} candidate spot(s) — manual inspection required` : "none detected"}</div>
                <div><span class="eyebrow">QUALITY</span> ${esc(eye.quality.blur)} · ${eye.quality.small ? "below reliable resolution" : "size adequate"}</div>
                <button class="btn small secondary" data-vf-magnify-box="${esc(JSON.stringify(eye.box))}" data-vf-magnify-title="Eye crop">Magnified crop</button>
              </div>
            </div>`).join("")}
        </div>`).join("") : `<p class="eyebrow">${esc(analysed?.eyes?.reason || "No face/eye analysis yet — run the full analysis.")}</p>`}
      ${capabilityFindings.length ? `<div class="vf-metric amber">${esc(capabilityFindings.map(f => f.title).join(" · "))}</div>` : ""}
      <details><summary>Add manual eye annotation</summary>
        <input id="vf-eye-label" placeholder="Label e.g. catchlight visible in left cornea" maxlength="120">
        <textarea id="vf-eye-note" rows="2" placeholder="Manual observation note (recorded as MANUAL source)"></textarea>
        <button class="btn small" data-vf-eye-annotate>Add manual annotation</button>
      </details>
    ` : ""}
  </div>`;
}

function vfLightingPanel() {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return "";
  const analysed = vf.analysed[image.id];
  const lighting = analysed?.lighting;
  const lightingFindings = vf.findings.filter(f => f.category === "lighting");
  return `<div class="panel">
    <div class="panel-head"><h2>5 · Shadow & lighting analysis</h2></div>
    ${lighting?.available ? `
      <div class="vf-lighting-grid">
        <div><img class="vf-illumination-map" src="${lighting.illuminationMap}" alt="Illumination map"
          style="width:160px;image-rendering:pixelated;border:1px solid var(--line);">
          <div class="eyebrow">Illumination map (brightness, low-res overlay)</div></div>
        <div>
          <div><span class="eyebrow">APPARENT LIGHT DIRECTION</span>
            <strong>${esc(lighting.apparentLightDirection || "indeterminate")}</strong>
            <span class="vf-badge">${esc(lighting.lightDirectionConfidence)}</span></div>
          <div><span class="eyebrow">UNEVEN ILLUMINATION</span> ${lighting.unevenIllumination ? "flagged" : "not flagged"}</div>
          <div><span class="eyebrow">SHADOW / GLARE CELLS</span> ${lighting.shadowCellCount} / ${lighting.glareCellCount}</div>
        </div>
      </div>
      <div class="vf-metric amber">${esc(lighting.limitations)}</div>
    ` : `<p class="eyebrow">Run the full analysis to compute lighting statistics.</p>`}
    ${lightingFindings.map(finding => `<div class="vf-metric"><strong>${esc(finding.title)}</strong> — ${esc(finding.description)}</div>`).join("")}
  </div>`;
}

function vfClarityPanel() {
  const vf = vfSetup();
  const image = vfImage();
  if (!image) return "";
  const enhancement = vf.enhancement;
  const derivatives = vf.derivatives;
  return `<div class="panel">
    <div class="panel-head"><h2>6 · Image clarity engine</h2>
      <span class="eyebrow amber">Processed copies are stored separately and never replace the original evidence</span></div>
    <div class="vf-clarity-controls">
      ${[["denoise", "Denoise", 0, 10, 0], ["sharpen", "Sharpen", 0, 10, 0],
        ["brightness", "Brightness", -100, 100, 0], ["contrast", "Contrast", -100, 100, 0],
        ["shadows", "Shadows lift", -100, 100, 0], ["highlights", "Highlight recovery", -100, 100, 0],
        ["gamma", "Gamma (0.1–3)", 0.1, 3, 1]].map(([key, label, min, max, step]) => `
        <label class="vf-slider"><span>${label}</span>
          <input type="range" id="vf-set-${key}" min="${min}" max="${max}" step="${step || 1}"
            value="${step ? 1 : 0}" oninput="this.nextElementSibling.textContent = this.value">
          <span class="vf-slider-value">${step ? 1 : 0}</span>
        </label>`).join("")}
      <label class="vf-slider"><span>Upscale</span>
        <select id="vf-set-upscale"><option value="1">1× (none)</option><option value="2">2×</option><option value="3">3×</option></select>
      </label>
    </div>
    <div class="vf-clarity-actions">
      <button class="btn" id="vf-enhance-run">Apply enhancement</button>
      <span class="eyebrow">${vf_image_note_enhancement()}</span>
    </div>
    ${enhancement ? `
      <div class="vf-enhancement-result">
        <div class="eyebrow green">PROCESSED COPY SAVED</div>
        <div class="vf-detail"><span class="eyebrow">PROCESSED SHA-256</span>${esc(enhancement.processedSha256)}</div>
        <div class="vf-detail"><span class="eyebrow">APPLIED</span>${esc(enhancement.applied.join(" · ") || "no effective changes")}</div>
        <div class="vf-detail amber">${esc(enhancement.superresolution.reason)}</div>
        <img src="${enhancement.processedImage}" class="vf-processed-preview" alt="Processed result" style="max-width:100%;border:1px solid var(--line);">
        <div class="vf-compare-strip">
          <div>Original: <span class="vf-hash">${esc(enhancement.originalSha256)}</span></div>
          <div>Processed: <span class="vf-hash">${esc(enhancement.processedSha256)}</span></div>
        </div>
      </div>` : ""}
    ${derivatives.length ? `<details><summary>Previous processed copies (${derivatives.length})</summary>
      ${derivatives.map(d => `<div class="vf-metric">
        <strong>${esc(d.kind)}</strong> ${esc(d.id)} · ${d.width}×${d.height} · ${esc(new Date(d.createdAt).toLocaleString())}<br>
        <span class="vf-hash">${esc(d.sha256)}</span><br>
        <button class="btn small secondary" data-vf-export-derivative="${esc(d.id)}">Export PNG</button></div>`).join("")}
    </details>` : ""}
  </div>`;
}

function vf_image_note_enhancement() {
  return "Sharpening does not reverse blur or restore information that was never captured.";
}

function vfComparePanel() {
  const vf = vfSetup();
  const compareData = vf.compareData;
  return `<div class="panel">
    <div class="panel-head"><h2>7 · Comparison workspace</h2>
      <button class="btn small" data-vf-compare-run>Run comparison</button></div>
    <div class="vf-compare-select">
      ${vf.images.map(img => `<label class="vf-toggle">
        <input type="checkbox" data-vf-compare-id="${esc(img.id)}" ${vf.compareIds.includes(img.id) ? "checked" : ""}>
        <img class="vf-thumb" src="${vfImageUrl(img.id)}" alt=""> ${esc(img.filename)}</label>`).join("")}
    </div>
    ${compareData ? `
      <div class="vf-compare-grid">
        ${compareData.images.map(img => `
          <div class="vf-compare-cell">
            <img src="${vfImageUrl(img.id)}" alt="${esc(img.filename)}" style="max-width:100%;border:1px solid var(--line);">
            <div><strong>${esc(img.filename)}</strong></div>
            <div class="eyebrow">${img.width}×${img.height} · ${esc(img.format)} · ${(img.byteSize / 1024).toFixed(0)} KB</div>
            <div class="vf-hash">${esc(img.sha256)}</div>
          </div>`).join("")}
      </div>
      ${compareData.metadataDiffs.map((diff, index) => `
        <details open><summary>Metadata differences: image 1 vs image ${index + 2}</summary>
          ${Object.keys(diff.diffs).length ? Object.entries(diff.diffs).map(([key, value]) => `
            <div class="vf-metric"><strong>${esc(key)}</strong>: ${esc(JSON.stringify(value[0]))} → ${esc(JSON.stringify(value[1]))}</div>`).join("")
          : `<div class="vf-metric">No differences in compared fields.</div>`}
        </details>`).join("")}
      <p class="eyebrow">Visual similarity is NOT proof that two images depict the same event, person, or location. This comparison does not identify individuals.</p>` : ""}
  </div>`;
}

function vfReportPanel() {
  const vf = vfSetup();
  const report = vf.reportPreview;
  return `<div class="panel">
    <div class="panel-head"><h2>8 · Investigation report</h2></div>
    <div class="vf-report-controls">
      <input id="vf-report-reviewer" placeholder="Reviewer (service number / name)" maxlength="80">
      <textarea id="vf-report-notes" rows="2" placeholder="Reviewer notes (human verification summary)"></textarea>
      <div class="vf-note-actions">
        <button class="btn" data-vf-report-generate>Generate report (JSON + CSV)</button>
        <button class="btn secondary" data-vf-report-print ${report ? "" : "disabled"}>Open print/PDF view</button>
      </div>
    </div>
    ${report ? `<div class="vf-report-preview">
      <h3>${esc(report.reportId)} · case ${esc(report.caseRef)}</h3>
      <div class="vf-report-sections">
        ${report.sections.map(section => `
          <details open><summary>${esc(section.image.filename)} — SHA-256 ${esc(section.image.sha256.slice(0, 24))}…</summary>
            <div class="vf-metric"><span class="eyebrow">ORIGINAL</span> ${esc(section.image.filename)} ·
              ${section.image.width}×${section.image.height} · ${esc(section.image.format)} ·
              SHA-256 ${esc(section.image.sha256)}</div>
            <div class="vf-metric"><span class="eyebrow">FINDINGS</span> ${section.findings.length}
              (confirmed ${section.findings.filter(f => f.reviewStatus === "Confirmed observation").length},
              rejected ${section.findings.filter(f => f.reviewStatus === "Rejected").length},
              inconclusive ${section.findings.filter(f => f.reviewStatus === "Inconclusive").length})</div>
            ${section.derivatives.length ? `<div class="vf-metric"><span class="eyebrow">ENHANCEMENTS</span>
              ${section.derivatives.map(d => `${esc(d.id)} (processed SHA-256 ${esc(d.sha256.slice(0, 16))}…) `).join(" · ")}</div>` : ""}
            ${section.findings.slice(0, 20).map(finding => `
              <div class="vf-metric ${finding.source === "model" || finding.source === "processing" ? "amber" : "green"}">
                <strong>${esc(finding.title)}</strong> [${esc(finding.reviewStatus)}] · ${esc(finding.source)} ·
                ${esc(finding.confidenceLabel)}<br>${esc(finding.description.slice(0, 280))}</div>`).join("")}
          </details>`).join("")}
      </div>
      <div class="vf-metric"><strong>Reviewer:</strong> ${esc(report.reviewer)}<br>
        <strong>Reviewer notes:</strong> ${esc(report.reviewerNotes || "—")}</div>
      <div class="vf-metric amber">${esc(report.limitationsStatement)}</div>
      <div class="vf-metric">${esc(report.admissibility)}</div>
    </div>` : ""}
  </div>`;
}

function vfModeChooser() {
  return `
    <div class="page-head"><div><button class="btn small secondary" data-back-to-tools>← Back to tools</button>
      <h1 style="margin-top:12px">AI Visual Forensics</h1>
      <p>CHOOSE AN ANALYSIS MODE TO BEGIN</p></div>
      <span class="simulated-badge">AI OUTPUT ≠ EVIDENCE</span></div>
    <div class="panel vf-mode-chooser">
      <div class="panel-head"><h2>What would you like to analyse?</h2>
        <span class="eyebrow">Select one to proceed</span></div>
      <div class="vf-mode-grid">
        <button class="vf-mode-card" data-vf-mode="image">
          <div class="vf-mode-icon">🖼</div>
          <div><strong>Analyse a picture</strong>
            <div class="eyebrow">JPEG · PNG · WEBP · TIFF — detection, quality, eye examination, lighting, clarity</div></div>
        </button>
        <button class="vf-mode-card" data-vf-mode="video" disabled>
          <div class="vf-mode-icon">🎞</div>
          <div><strong>Analyse a video</strong>
            <div class="eyebrow">Coming soon — frame-by-frame video analysis is not yet supported.</div></div>
        </button>
      </div>
    </div>`;
}

function vfSetMode(mode) {
  const vf = vfSetup();
  if (mode !== "image") {
    toast("Video analysis is not available yet. Please analyse a picture for now.", true);
    return;
  }
  vf.mode = mode;
  renderVisualForensics(document.getElementById("page-content"));
  vfLoadImages();
}

function renderVisualForensics(content) {
  const vf = vfSetup();
  if (vf.mode !== "image") {
    content.innerHTML = vfModeChooser();
    content.querySelectorAll("[data-vf-mode]").forEach(node =>
      node.addEventListener("click", () => vfSetMode(node.dataset.vfMode)));
    return;
  }
  content.innerHTML = `
    <div class="page-head"><div><button class="btn small secondary" data-back-to-tools>← Back to tools</button>
      <h1 style="margin-top:12px">AI Visual Forensics</h1>
      <p>IMAGE INTAKE · DETECTION · QUALITY · EYE EXAMINATION · LIGHTING · CLARITY · COMPARISON · REPORTING</p></div>
      <span class="simulated-badge">AI OUTPUT ≠ EVIDENCE</span></div>
    ${vf.error ? `<div class="home-banner vf-notice"><strong class="warning">BACKEND ERROR:</strong> ${esc(vf.error)}</div>` : ""}
    <div class="home-banner vf-notice"><strong>HOW TO READ THIS TOOL.</strong>
      <span class="vf-badge">PROCESSING</span> and <span class="vf-badge">AI MODEL</span> items are algorithmic, not forensic conclusions.</div>
    <div class="vf-grid">
      <div class="vf-col-main">${vfViewerPanel()}${vfUploadPanel()}${vfFindingsPanel()}${vfEyePanel()}${vfLightingPanel()}</div>
      <div class="vf-col-side">${vfClarityPanel()}${vfComparePanel()}${vfReportPanel()}</div>
    </div>`;

  // --- Upload wiring
  const dropzone = content.querySelector("#vf-dropzone");
  const fileInput = content.querySelector("#vf-file-input");
  if (dropzone && fileInput) {
    dropzone.addEventListener("click", () => fileInput.click());
    dropzone.addEventListener("keydown", event => { if (event.key === "Enter") fileInput.click(); });
    dropzone.addEventListener("dragover", event => { event.preventDefault(); dropzone.classList.add("dragover"); });
    dropzone.addEventListener("dragleave", () => dropzone.classList.remove("dragover"));
    dropzone.addEventListener("drop", event => {
      event.preventDefault(); dropzone.classList.remove("dragover");
      vfUploadFiles(event.dataTransfer.files);
    });
    fileInput.addEventListener("change", () => { vfUploadFiles(fileInput.files); fileInput.value = ""; });
  }

  // --- Viewer wiring
  const viewport = content.querySelector("#vf-viewport");
  if (viewport) {
    let panning = false, lastX = 0, lastY = 0, regionStart = null;
    viewport.addEventListener("wheel", event => {
      event.preventDefault();
      const box = viewport.getBoundingClientRect();
      vfZoomBy(event.deltaY < 0 ? 1.2 : 1 / 1.2, event.clientX - box.left, event.clientY - box.top);
    }, { passive: false });
    viewport.addEventListener("mousedown", event => {
      if (event.target.closest(".vf-magnifier")) return;
      if (event.shiftKey) {
        const rect = viewport.getBoundingClientRect();
        regionStart = { x: event.clientX - rect.left, y: event.clientY - rect.top };
      } else {
        panning = true; lastX = event.clientX; lastY = event.clientY;
      }
    });
    window.addEventListener("mousemove", event => {
      if (panning) {
        vf.viewer.panX += event.clientX - lastX;
        vf.viewer.panY += event.clientY - lastY;
        lastX = event.clientX; lastY = event.clientY;
        vf.viewer.fit = false;
        vfApplyViewerTransform();
      } else if (regionStart) {
        const rect = viewport.getBoundingClientRect();
        const width = event.clientX - rect.left - regionStart.x;
        const height = event.clientY - rect.top - regionStart.y;
        let node = document.querySelector(".vf-region-box");
        if (!node) {
          node = document.createElement("div");
          node.className = "vf-region-box";
          document.querySelector(".vf-image-stage").appendChild(node);
        }
        node.style.left = `${Math.min(regionStart.x, regionStart.x + width)}px`;
        node.style.top = `${Math.min(regionStart.y, regionStart.y + height)}px`;
        node.style.width = `${Math.abs(width)}px`;
        node.style.height = `${Math.abs(height)}px`;
      }
    });
    window.addEventListener("mouseup", event => {
      if (regionStart) {
        const rect = viewport.getBoundingClientRect();
        const image = vfImage();
        const endX = event.clientX - rect.left, endY = event.clientY - rect.top;
        const x0 = Math.min(regionStart.x, endX), y0 = Math.min(regionStart.y, endY);
        const w = Math.abs(endX - regionStart.x), h = Math.abs(endY - regionStart.y);
        regionStart = null;
        if (w > 8 && h > 8 && image) {
          const label = prompt("Region annotation label:", "Analyst-highlighted region");
          if (label) vfAddAnnotation([x0 / vf.viewer.zoom, y0 / vf.viewer.zoom, w / vf.viewer.zoom, h / vf.viewer.zoom], label, "Drawn with region select");
          else document.querySelector(".vf-region-box")?.remove();
        } else document.querySelector(".vf-region-box")?.remove();
      }
      panning = false;
    });
    viewport.addEventListener("dblclick", event => {
      const overlay = event.target.closest(".vf-overlay-box");
      if (overlay) {
        const box = JSON.parse(overlay.dataset.box);
        vfMagnifyBox(box, overlay.title, "Original pixels");
      }
    });
    const slider = content.querySelector("#vf-compare-slider");
    if (slider) {
      const handle = slider.querySelector(".vf-compare-handle");
      const overlay = content.querySelector("#vf-compare-overlay");
      let sliding = false;
      const move = event => {
        if (!sliding) return;
        const rect = slider.getBoundingClientRect();
        const pct = Math.min(100, Math.max(0, ((event.clientX - rect.left) / rect.width) * 100));
        handle.style.left = `${pct}%`;
        overlay.style.clipPath = `inset(0 ${100 - pct}% 0 0)`;
      };
      slider.addEventListener("mousedown", event => { sliding = true; move(event); });
      window.addEventListener("mousemove", move);
      window.addEventListener("mouseup", () => { sliding = false; });
    }
    // After the image loads, fit it to the viewport at zoom 1.
    const stageImage = content.querySelector(".vf-stage-img");
    if (stageImage) {
      const fit = () => { Object.assign(vf.viewer, { zoom: 1, panX: 0, panY: 0 }); vfFitNatural(); };
      if (stageImage.complete && stageImage.naturalWidth) fit();
      else stageImage.addEventListener("load", fit, { once: true });
    }
  }

  // --- Viewer toolbar (lives outside the viewport, so it must not depend on it)
  content.querySelectorAll("[data-vf-zoom]").forEach(button => button.addEventListener("click", () => {
    vfZoomBy(button.dataset.vfZoom === "in" ? 1.3 : 1 / 1.3);
  }));
  const fitButton = content.querySelector("[data-vf-fit]");
  if (fitButton) fitButton.addEventListener("click", vfFitNatural);
  const fullscreenButton = content.querySelector("[data-vf-fullscreen]");
  if (fullscreenButton) fullscreenButton.addEventListener("click", () => {
    const target = content.querySelector("#vf-viewport");
    if (!target) return;
    if (document.fullscreenElement) document.exitFullscreen();
    else target.requestFullscreen().catch(() => toast("Fullscreen unavailable.", true));
  });
  const findingsToggle = content.querySelector("#vf-toggle-findings");
  if (findingsToggle) findingsToggle.addEventListener("change", () => {
    vf.showFindings = findingsToggle.checked;
    renderVisualForensics(content);
  });
  const annotationsToggle = content.querySelector("#vf-toggle-annotations");
  if (annotationsToggle) annotationsToggle.addEventListener("change", () => {
    vf.showAnnotations = annotationsToggle.checked;
    renderVisualForensics(content);
  });
  const compareToggle = content.querySelector("#vf-toggle-compare");
  if (compareToggle) compareToggle.addEventListener("change", event => {
    const overlay = content.querySelector("#vf-compare-overlay");
    if (overlay) overlay.style.display = event.target.checked ? "block" : "none";
  });

  // --- Findings wiring
  content.querySelectorAll("[data-vf-select]").forEach(node =>
    node.addEventListener("click", () => vfSelectImage(node.dataset.vfSelect)));
  content.querySelectorAll("[data-vf-remove]").forEach(node =>
    node.addEventListener("click", event => {
      event.stopPropagation();
      vfDeleteImage(node.dataset.vfRemove);
    }));
  content.querySelectorAll("[data-vf-analyse]").forEach(node =>
    node.addEventListener("click", () => vfAnalyse(node.dataset.vfAnalyse)));
  content.querySelectorAll("[data-vf-open-finding]").forEach(node =>
    node.addEventListener("click", () => {
      const vf2 = vfSetup();
      vf2.selectedFindingId = vf2.selectedFindingId === node.dataset.vfOpenFinding ? null : node.dataset.vfOpenFinding;
      renderVisualForensics(content);
    }));
  content.querySelectorAll("[data-vf-jump]").forEach(node =>
    node.addEventListener("click", () => {
      const vf2 = vfSetup();
      const finding = vf2.findings.find(f => f.id === node.dataset.vfJump);
      if (finding) vfJumpToBox(finding.box);
    }));
  content.querySelectorAll("[data-vf-magnify]").forEach(node =>
    node.addEventListener("click", () => {
      const vf2 = vfSetup();
      const finding = vf2.findings.find(f => f.id === node.dataset.vfMagnify);
      if (finding) vfMagnifyBox(finding.box, finding.title, finding.source);
    }));
  content.querySelectorAll("[data-vf-magnify-box]").forEach(node =>
    node.addEventListener("click", () => {
      vfMagnifyBox(JSON.parse(node.dataset.vfMagnifyBox), node.dataset.vfMagnifyTitle || "Region", "Original pixels");
    }));
  const confirmFinding = async (findingId, status) => {
    const note = document.getElementById(`vf-note-${findingId}`)?.value.trim()
      || (status === "Confirmed observation" ? "Visual feature verified by analyst." : "");
    await vfFindingReview(findingId, status, note);
  };
  content.querySelectorAll("[data-vf-confirm]").forEach(node =>
    node.addEventListener("click", () => confirmFinding(node.dataset.vfConfirm, "Confirmed observation")));
  content.querySelectorAll("[data-vf-reject]").forEach(node =>
    node.addEventListener("click", () => {
      const note = document.getElementById(`vf-note-${node.dataset.vfReject}`)?.value.trim();
      if (!note) return toast("Enter a reason in the note field before rejecting.", true);
      vfFindingReview(node.dataset.vfReject, "Rejected", note);
    }));
  content.querySelectorAll("[data-vf-inconclusive]").forEach(node =>
    node.addEventListener("click", () => {
      const note = document.getElementById(`vf-note-${node.dataset.vfInconclusive}`)?.value.trim();
      if (!note) return toast("Enter a reason in the note field before marking inconclusive.", true);
      vfFindingReview(node.dataset.vfInconclusive, "Inconclusive", note);
    }));
  content.querySelectorAll("[data-vf-note]").forEach(node =>
    node.addEventListener("click", () => {
      const note = document.getElementById(`vf-note-${node.dataset.vfNote}`)?.value.trim();
      if (!note) return toast("Write a note first.", true);
      vfFindingNote(node.dataset.vfNote, note);
    }));
  content.querySelectorAll("[data-vf-note-confirm]").forEach(node =>
    node.addEventListener("click", () => {
      const note = document.getElementById(`vf-note-${node.dataset.vfNoteConfirm}`)?.value.trim();
      if (!note) return toast("Write the note recording what you verified first.", true);
      vfFindingReview(node.dataset.vfNoteConfirm, "Confirmed observation", note);
    }));

  // --- Eye / lighting wiring
  const eyeToggle = content.querySelector("[data-vf-eye-toggle]");
  if (eyeToggle) eyeToggle.addEventListener("click", () => {
    vf.eyePanelOpen = !vf.eyePanelOpen;
    renderVisualForensics(content);
  });
  // (Everything below is registered once per page load: renderVisualForensics() replaces
  // only #page-content, so putting these inside the render would stack duplicate handlers.)
  vfBindGlobalActions();
}

function vfBindGlobalActions() {
  if (vfSetup().actionsBound) return;
  vfSetup().actionsBound = true;
  const handler = (selector, eventName, callback) => document.addEventListener(eventName, event => {
    const node = event.target.closest?.(selector);
    if (!node || !node.closest("#page-content")) return;
    callback(node, event);
  });

  handler("[data-vf-eye-annotate]", "click", () => {
    const label = document.getElementById("vf-eye-label")?.value.trim();
    const note = document.getElementById("vf-eye-note")?.value.trim() || "";
    if (!label) return toast("Enter a label for the manual annotation.", true);
    const vf = vfSetup();
    const analysed = vf.analysed[vf.selectedId];
    const firstEye = analysed?.eyes?.faces?.[0]?.eyes?.[0]?.box;
    vfAddAnnotation(firstEye || [0, 0, Math.round((vfImage()?.width || 0) / 4), Math.round((vfImage()?.height || 0) / 4)], label, note);
  });

  // --- Clarity wiring
  handler("#vf-enhance-run", "click", vfApplyEnhancement);
  handler("[data-vf-export-derivative]", "click", node => {
    const derivative = vfSetup().derivatives.find(d => d.id === node.dataset.vfExportDerivative);
    if (derivative) vfExportDerivative(derivative);
  });

  // --- Comparison wiring
  handler("[data-vf-compare-id]", "change", node => {
    const vf = vfSetup();
    const id = node.dataset.vfCompareId;
    if (node.checked) { if (!vf.compareIds.includes(id)) vf.compareIds.push(id); }
    else vf.compareIds = vf.compareIds.filter(existing => existing !== id);
  });
  handler("[data-vf-compare-run]", "click", vfRunComparison);

  // --- Report wiring
  handler("[data-vf-report-generate]", "click", vfGenerateReport);
  handler("[data-vf-report-print]", "click", () => {
    const vf2 = vfSetup();
    if (!vf2.reportPreview) return;
    const printWindow = window.open("", "_blank", "width=900,height=700");
    if (!printWindow) return toast("Allow pop-ups to open the print/PDF view.", true);
    const report = vf2.reportPreview;
    printWindow.document.write(`<!DOCTYPE html><html><head><title>${esc(report.reportId)} · Visual Forensics report</title>
      <style>body{font-family:Georgia,serif;margin:2.5em;color:#111}h1{font-size:1.4em}h2{font-size:1.1em;margin-top:1.6em}
      .meta{font-family:monospace;font-size:.85em;color:#444}.ai{color:#8a6d3b}.human{color:#1a6b3c}
      .section{border:1px solid #bbb;padding:1em;margin-bottom:1em}footer{font-size:.8em;color:#555}</style></head><body>
      <h1>Visual Forensics Investigation Report · ${esc(report.reportId)}</h1>
      <p class="meta">Case: ${esc(report.caseRef)} · Analyst: ${esc(report.analyst)} · Reviewer: ${esc(report.reviewer)} ·
      Generated: ${esc(new Date(report.generatedAt).toISOString())}</p>
      ${report.sections.map(section => `<div class="section">
        <h2>${esc(section.image.filename)}</h2>
        <p class="meta">Dimensions ${section.image.width}×${section.image.height} · ${esc(section.image.format)} ·
        ${(section.image.byteSize / 1024).toFixed(0)} KB<br>Original SHA-256: ${esc(section.image.sha256)}</p>
        <h3>Findings</h3>
        ${section.findings.length ? section.findings.map(finding => `
          <p class="${finding.source === "model" || finding.source === "processing" ? "ai" : "human"}">
            <strong>${esc(finding.title)}</strong> [${esc(finding.reviewStatus)}] —
            source: ${esc(finding.source)} · confidence: ${esc(finding.confidenceLabel)}<br>
            ${esc(finding.description)}<br>
            <em>Limitations: ${esc(finding.limitations)}</em></p>`).join("") : "<p>No findings recorded.</p>"}
        ${section.derivatives.length ? `<h3>Enhancement operations</h3>
          ${section.derivatives.map(d => `<p class="meta">Processed copy ${esc(d.id)} — processed SHA-256: ${esc(d.sha256)} ·
          settings: ${esc(JSON.stringify(d.settings))}</p>`).join("")}` : ""}
      </div>`).join("")}
      <h2>Reviewer notes</h2><p>${esc(report.reviewerNotes || "—")}</p>
      <h2>Limitations</h2><p>${esc(report.limitationsStatement)}</p>
      <p class="meta">${esc(report.admissibility)}</p>
      <footer>Generated by ROUGE Visual Forensics prototype. Not verified for legal admissibility.</footer>
      </body></html>`);
    printWindow.document.close();
    printWindow.focus();
    setTimeout(() => printWindow.print(), 500);
  });
}
