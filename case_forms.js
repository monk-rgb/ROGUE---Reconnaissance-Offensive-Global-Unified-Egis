"use strict";

(() => {
  const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, character => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  })[character]);
  let leafletPromise;

  async function loadLeaflet() {
    if (window.L) return window.L;
    if (!leafletPromise) {
      leafletPromise = new Promise((resolve, reject) => {
        const css = document.createElement("link");
        css.rel = "stylesheet";
        css.href = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.css";
        document.head.append(css);
        const script = document.createElement("script");
        script.src = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.js";
        script.onload = () => window.L ? resolve(window.L) : reject(new Error("Leaflet loaded without its map API."));
        script.onerror = () => reject(new Error("Leaflet could not be loaded."));
        document.head.append(script);
      });
    }
    return leafletPromise;
  }

  function listInput(id, label, placeholder = "") {
    return `<div class="field"><label for="${id}">${label}</label><input id="${id}" maxlength="600" placeholder="${placeholder}"></div>`;
  }

  function render(prefix, family) {
    const id = name => `${prefix}-${name}`;
    const field = (name, label, options = {}) => `
      <div class="field ${options.full ? "full" : ""}">
        <label for="${id(name)}">${label}${options.sensitive ? ` <span class="case-sensitive">SENSITIVE</span>` : ""}</label>
        ${options.textarea
          ? `<textarea id="${id(name)}" maxlength="${options.maxlength || 1200}" ${options.required ? "required" : ""} placeholder="${options.placeholder || ""}"></textarea>`
          : `<input id="${id(name)}" type="${options.type || "text"}" maxlength="${options.maxlength || 240}" ${options.required ? "required" : ""} ${options.attrs || ""} placeholder="${options.placeholder || ""}">`}
      </div>`;
    return `
      <form id="${id("case-report-form")}" class="panel-body case-form" data-case-prefix="${prefix}" data-family="${family}">
        <div class="form-grid">
          <div class="field"><label for="${id("case-type")}">Case type</label><select id="${id("case-type")}">
            <option>Missing person</option><option>Suspected kidnapping</option><option>Abduction of a minor</option>
          </select></div>
          ${field("full-name", "Person's full name", { required:true })}
          ${listInput(id("other-names"), "Other names", "One or more names separated by commas")}
          ${field("age", "Age", { type:"number", attrs:'min="0" max="120" inputmode="numeric"', placeholder:"Enter age or date of birth" })}
          ${field("dob", "Date of birth", { type:"date" })}
          <div class="field"><label for="${id("sex")}">Sex</label><select id="${id("sex")}"><option>Not known</option><option>Female</option><option>Male</option><option>Other</option></select></div>
          ${field("height", "Height", { placeholder:"e.g. 165 cm" })}
          ${field("marks", "Distinguishing marks", { textarea:true, full:true })}
          ${field("clothing", "Clothing last seen in", { textarea:true, full:true })}
          ${field("medical", "Medical needs / medication", { textarea:true, full:true, sensitive:true })}
          ${listInput(id("languages"), "Languages spoken", "Comma-separated")}
          ${field("nin", "NIN · optional", { maxlength:32 })}
          ${family ? field("ransom", "Ransom demand", { textarea:true, full:true, sensitive:true }) : ""}
          <div class="field full"><label for="${id("photos")}">Recent photos · upload 1–5</label>
            <input id="${id("photos")}" type="file" accept="image/png,image/jpeg,image/webp" multiple required>
            <span class="muted">Clear, recent photos: front-facing, well lit, no sunglasses. Each image max 2 MB.</span>
            <div id="${id("photo-preview")}" class="case-photo-grid"></div>
            <div id="${id("photo-checks")}" class="case-photo-checks" role="status" aria-live="polite">Photo checks will appear here. These checks assess image quality only; they do not identify a person.</div>
          </div>
          ${field("place", "Last-known place name", { required:true })}
          ${field("state", "State", { required:true })}
          ${field("lga", "LGA")}
          ${field("location-time", "Last known · date and time", { type:"datetime-local" })}
          <div class="field"><label for="${id("accuracy")}">Location accuracy</label><select id="${id("accuracy")}"><option value="exact">Exact</option><option value="area">Area</option><option value="unsure">Unsure</option></select></div>
          <div class="field full"><label>Map pin · optional when unsure</label><div id="${id("map")}" class="case-map" role="application" aria-label="Last-known location map"></div><div id="${id("map-message")}" class="muted case-map-message">Choose a map point or enter coordinates below. The map may be unavailable offline.</div></div>
          ${field("latitude", "Latitude", { type:"number", attrs:'step="any" min="4" max="14"', placeholder:"4–14" })}
          ${field("longitude", "Longitude", { type:"number", attrs:'step="any" min="2" max="15"', placeholder:"2–15" })}
          ${field("happened", "What happened?", { textarea:true, full:true, required:true, maxlength:3000 })}
          ${field("last-with", "Who was last with the person?", { textarea:true, full:true })}
          ${field("vehicle", "Vehicle details, if known", { textarea:true, full:true })}
          ${family ? "" : field("case-notes", "Case notes · officer record", { textarea:true, full:true, maxlength:8000, placeholder:"Anything officers should know that does not fit the fields above: background, lines of enquiry, contacts, evidence and photo context." })}
          ${field("reporter-name", "Reporter name", { required:true })}
          ${field("relationship", "Relationship to person", { required:true })}
          ${field("phone", "Reporter phone", { type:"tel", required:true })}
          ${field("email", family ? "Reporter email · verification required" : "Reporter email", { type:"email", required:true })}
        </div>
        ${family ? `<div class="case-verification panel"><div class="panel-heading"><h2>Verify your email</h2></div><div class="panel-body">
          <div class="case-verification-row"><button class="btn secondary" id="${id("send-code")}" type="button">Send code</button><label class="sr-only" for="${id("email-code")}">Six-digit email verification code</label><input id="${id("email-code")}" inputmode="numeric" autocomplete="one-time-code" maxlength="6" placeholder="6-digit code"><button class="btn secondary" id="${id("verify-code")}" type="button">Verify email</button></div>
          <p id="${id("verification-message")}" class="message" role="status"></p>
          <input type="hidden" id="${id("verification-token")}">
        </div></div>` : ""}
        <div class="case-consent">
          <label><input id="${id("consent-accurate")}" type="checkbox" required> I confirm the information is accurate to the best of my knowledge.</label>
          <label><input id="${id("consent-authorised")}" type="checkbox" required> I am authorised to make this report and consent to its use for locating the person.</label>
          <label><input id="${id("consent-adult")}" type="checkbox"> For an adult: I am reporting on their behalf and understand it may be closed if they are found safe and do not want contact.</label>
        </div>
        <label class="case-honeypot" aria-hidden="true">Leave this field empty<input id="${id("website")}" tabindex="-1" autocomplete="off"></label>
        <p class="muted case-privacy">Medical details are sensitive and visible only to authorised case officers. Family status lookup reveals status updates only, never case files or officer notes.</p>
        <p id="${id("message")}" class="message" role="status"></p>
        <div class="form-actions"><button class="btn amber-btn" type="submit">${family ? "Submit missing-person report" : "Create case for review"}</button></div>
      </form>`;
  }

  async function imageCheck(file) {
    const bitmap = await createImageBitmap(file);
    const canvas = document.createElement("canvas");
    const scale = Math.min(1, 192 / Math.max(bitmap.width, bitmap.height));
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const context = canvas.getContext("2d", { willReadFrequently:true });
    context.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const { data } = context.getImageData(0, 0, canvas.width, canvas.height);
    let faceResult = "face detection unavailable in this browser; officer visual check required";
    const warnings = [];
    if ("FaceDetector" in window) {
      try {
        const detected = await new window.FaceDetector({ fastMode:true, maxDetectedFaces:5 }).detect(bitmap);
        faceResult = detected.length ? `${detected.length} face(s) detected` : "no face detected";
        if (!detected.length) warnings.push("no face detected");
      } catch {
        warnings.push("automatic face detection failed");
      }
    } else {
      warnings.push("automatic face detection unavailable");
    }
    bitmap.close();
    const grey = new Float32Array(canvas.width * canvas.height);
    let light = 0;
    for (let i = 0; i < grey.length; i++) {
      const offset = i * 4;
      grey[i] = .299 * data[offset] + .587 * data[offset + 1] + .114 * data[offset + 2];
      light += grey[i];
    }
    const mean = light / grey.length;
    let lapSum = 0, lapSquared = 0, samples = 0;
    for (let y = 1; y < canvas.height - 1; y++) for (let x = 1; x < canvas.width - 1; x++) {
      const index = y * canvas.width + x;
      const laplacian = grey[index - canvas.width] + grey[index + canvas.width] +
        grey[index - 1] + grey[index + 1] - 4 * grey[index];
      lapSum += laplacian;
      lapSquared += laplacian * laplacian;
      samples++;
    }
    const blurVariance = samples ? lapSquared / samples - (lapSum / samples) ** 2 : 0;
    if (blurVariance < 45) warnings.push("may be blurry");
    if (mean < 35 || mean > 225) warnings.push("lighting may be poor");
    return { name:file.name, blurVariance:Math.round(blurVariance), averageBrightness:Math.round(mean), faceResult, warnings };
  }

  async function read(prefix) {
    const id = name => `${prefix}-${name}`;
    const photoInput = document.getElementById(id("photos"));
    const photos = [...(photoInput?.files || [])];
    if (!photos.length || photos.length > 5) throw new Error("Upload between one and five recent photos.");
    if (photos.some(file => !["image/png", "image/jpeg", "image/webp"].includes(file.type) || file.size > 2 * 1024 * 1024)) {
      throw new Error("Each photo must be PNG, JPEG, or WebP and no larger than 2 MB.");
    }
    const photoChecks = await Promise.all(photos.map(imageCheck));
    const photoUrls = await Promise.all(photos.map(file => new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(reader.result);
      reader.onerror = () => reject(reader.error || new Error("Could not read a photo."));
      reader.readAsDataURL(file);
    })));
    const value = name => document.getElementById(id(name)).value.trim();
    const list = name => value(name).split(/[,\n]/).map(item => item.trim()).filter(Boolean);
    const age = value("age");
    const dob = value("dob");
    if ((!age && !dob) || (age && dob)) throw new Error("Enter either age or date of birth.");
    const lat = value("latitude"), lon = value("longitude");
    const family = document.getElementById(`${prefix}-case-report-form`).dataset.family === "true";
    const adultOnBehalf = document.getElementById(id("consent-adult")).checked;
    const effectiveAge = age ? Number(age) : dob ? (() => {
      const birth = new Date(`${dob}T00:00:00`);
      const today = new Date();
      return today.getFullYear() - birth.getFullYear() -
        (today.getMonth() < birth.getMonth() ||
          (today.getMonth() === birth.getMonth() && today.getDate() < birth.getDate()) ? 1 : 0);
    })() : null;
    if (family && effectiveAge >= 18 && !adultOnBehalf) {
      throw new Error("For an adult, confirm you are reporting on their behalf.");
    }
    return {
      caseType:document.getElementById(id("case-type")).value,
      person:{
        fullName:value("full-name"), otherNames:list("other-names"), age:age ? Number(age) : null,
        dateOfBirth:dob, sex:document.getElementById(id("sex")).value, height:value("height"),
        distinguishingMarks:value("marks"), clothingLastSeen:value("clothing"),
        medicalNeeds:value("medical"), languages:list("languages"), nin:value("nin")
      },
      photos:photoUrls, photoChecks,
      location:{
        placeName:value("place"), state:value("state"), lga:value("lga"),
        latitude:lat ? Number(lat) : null, longitude:lon ? Number(lon) : null,
        time:value("location-time"), accuracy:document.getElementById(id("accuracy")).value
      },
      circumstances:{
        whatHappened:value("happened"), lastWith:value("last-with"),
        vehicleDetails:value("vehicle"), ransomDemand:""
      },
      caseNotes:family ? "" : value("case-notes"),
      reporter:{name:value("reporter-name"), relationship:value("relationship"), phone:value("phone"), email:value("email")},
      consent:{
        accuracyConfirmed:document.getElementById(id("consent-accurate")).checked,
        authorisedToReport:document.getElementById(id("consent-authorised")).checked,
        adultOnBehalf
      },
      website:value("website"),
      verificationToken:family ? value("verification-token") : ""
    };
  }

  async function initMap(prefix) {
    const mapNode = document.getElementById(`${prefix}-map`);
    if (!mapNode) return;
    try {
      const L = await loadLeaflet();
      if (!mapNode.isConnected) return;
      const map = L.map(mapNode).setView([9.08, 8.67], 5);
      L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}", {
        attribution:"Tiles © Esri", maxZoom:18
      }).addTo(map);
      let marker = null;
      map.on("click", event => {
        const { lat, lng } = event.latlng;
        if (lat < 4 || lat > 14 || lng < 2 || lng > 15) {
          document.getElementById(`${prefix}-map-message`).textContent = "Choose a point inside Nigeria.";
          return;
        }
        if (marker) marker.setLatLng(event.latlng);
        else marker = L.marker(event.latlng).addTo(map);
        document.getElementById(`${prefix}-latitude`).value = lat.toFixed(6);
        document.getElementById(`${prefix}-longitude`).value = lng.toFixed(6);
        document.getElementById(`${prefix}-map-message`).textContent = `Map pin selected: ${lat.toFixed(5)}, ${lng.toFixed(5)}.`;
      });
      map.invalidateSize();
    } catch (error) {
      mapNode.innerHTML = `<div class="case-map-fallback">Offline map: enter coordinates manually. ${escapeHtml(error.message)}</div>`;
    }
  }

  async function renderCaseMap(containerId, caseRecord) {
    const node = document.getElementById(containerId);
    const message = document.getElementById("case-detail-map-message");
    if (!node) return;
    try {
      const L = await loadLeaflet();
      if (!node.isConnected) return;
      const last = caseRecord.location;
      const points = [];
      if (Number.isFinite(last.latitude) && Number.isFinite(last.longitude)) {
        points.push([last.latitude, last.longitude]);
      }
      for (const event of caseRecord.timeline || []) {
        if (event.event !== "sighting_added") continue;
        const lat = Number(event.details.latitude), lon = Number(event.details.longitude);
        if (Number.isFinite(lat) && Number.isFinite(lon)) points.push([lat, lon]);
      }
      const centre = points[0] || [9.08, 8.67];
      const map = L.map(node).setView(centre, points.length ? 8 : 5);
      L.tileLayer("https://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/{z}/{y}/{x}", {
        attribution:"Tiles © Esri", maxZoom:18
      }).addTo(map);
      if (Number.isFinite(last.latitude) && Number.isFinite(last.longitude)) {
        L.marker([last.latitude, last.longitude]).addTo(map).bindPopup("Last known location");
      }
      for (const event of caseRecord.timeline || []) {
        if (event.event !== "sighting_added") continue;
        const lat = Number(event.details.latitude), lon = Number(event.details.longitude);
        if (Number.isFinite(lat) && Number.isFinite(lon)) {
          L.circleMarker([lat, lon], { color:"#e5a84c" }).addTo(map)
            .bindPopup(`${escapeHtml(event.details.placeName)} · ${escapeHtml(event.details.confidence)} confidence`);
        }
      }
      if (message) message.textContent = points.length ? "Last-known location and pinned sightings." : "No map pins were recorded; location names remain in the case timeline.";
      setTimeout(() => map.invalidateSize(), 0);
    } catch (error) {
      node.innerHTML = `<div class="case-map-fallback">Offline map · location names and coordinates remain available in the case record. ${escapeHtml(error.message)}</div>`;
      if (message) message.textContent = "Leaflet is unavailable; offline case details remain available.";
    }
  }

  function bindPhotoChecks(prefix) {
    const input = document.getElementById(`${prefix}-photos`);
    if (!input) return;
    input.addEventListener("change", async () => {
      const preview = document.getElementById(`${prefix}-photo-preview`);
      const checks = document.getElementById(`${prefix}-photo-checks`);
      preview.innerHTML = "";
      if (input.files.length > 5) {
        input.value = "";
        checks.textContent = "Maximum five photos per report.";
        return;
      }
      try {
        const results = await Promise.all([...input.files].map(async file => ({
          file, check:await imageCheck(file)
        })));
        for (const { file, check } of results) {
          const image = document.createElement("img");
          image.src = URL.createObjectURL(file);
          image.alt = `Preview of ${file.name}`;
          preview.append(image);
          const warningText = check.warnings.length ? `Warning: ${check.warnings.join(", ")}.` : "Basic quality check passed.";
          checks.append(document.createTextNode(`${file.name}: ${check.faceResult}; ${warningText} `));
        }
        if (!input.files.length) checks.textContent = "Photo checks will appear here.";
      } catch (error) {
        checks.textContent = `Could not check the selected photos: ${error.message}`;
      }
    });
  }

  window.CaseManagementForms = { render, read, initMap, renderCaseMap, bindPhotoChecks };
})();
