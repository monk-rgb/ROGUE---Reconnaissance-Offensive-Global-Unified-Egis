"use strict";

(() => {
  const host = document.getElementById("family-form-host");
  const prefix = "family-case";
  const escapeHtml = value => String(value ?? "").replace(/[&<>"']/g, character => ({
    "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;"
  })[character]);
  host.innerHTML = window.CaseManagementForms.render(prefix, true);
  window.CaseManagementForms.bindPhotoChecks(prefix);
  window.CaseManagementForms.initMap(prefix);

  const form = document.getElementById(`${prefix}-case-report-form`);
  const verificationMessage = document.getElementById(`${prefix}-verification-message`);
  const setMessage = (node, message, error = false) => {
    node.textContent = message;
    node.className = `message ${error ? "error" : "success"}`;
  };
  const api = async (path, payload) => {
    const response = await fetch(path, {
      method:"POST", headers:{"Content-Type":"application/json"},
      body:JSON.stringify(payload)
    });
    const result = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(result.error || `Request failed (${response.status}).`);
    return result;
  };

  document.getElementById(`${prefix}-send-code`).addEventListener("click", async () => {
    const email = document.getElementById(`${prefix}-email`).value.trim();
    if (!email) return setMessage(verificationMessage, "Enter the reporter email first.", true);
    try {
      const result = await api("/api/family/verification/request", { email });
      form.querySelector(`#${prefix}-verification-token`).value = "";
      verificationMessage.dataset.verificationId = result.verificationId;
      setMessage(verificationMessage, result.message);
    } catch (error) {
      setMessage(verificationMessage, error.message, true);
    }
  });
  document.getElementById(`${prefix}-verify-code`).addEventListener("click", async () => {
    const code = document.getElementById(`${prefix}-email-code`).value.trim();
    const verificationId = verificationMessage.dataset.verificationId;
    if (!verificationId) return setMessage(verificationMessage, "Request an email code first.", true);
    try {
      const result = await api("/api/family/verification/confirm", { verificationId, code });
      form.querySelector(`#${prefix}-verification-token`).value = result.verificationToken;
      setMessage(verificationMessage, result.message);
    } catch (error) {
      setMessage(verificationMessage, error.message, true);
    }
  });

  form.addEventListener("submit", async event => {
    event.preventDefault();
    const message = document.getElementById(`${prefix}-message`);
    try {
      const payload = await window.CaseManagementForms.read(prefix);
      const result = await api("/api/family/cases", payload);
      document.getElementById("status-reference").value = result.report.reference;
      document.getElementById("status-token").value = result.statusCheckToken;
      setMessage(message, `${result.message} Report reference: ${result.report.reference}. Keep the private status-check token shown in the status form.`);
    } catch (error) {
      setMessage(message, error.message, true);
    }
  });

  document.getElementById("family-status-form").addEventListener("submit", async event => {
    event.preventDefault();
    const reference = document.getElementById("status-reference").value.trim();
    const token = document.getElementById("status-token").value.trim();
    const message = document.getElementById("family-status-message");
    const resultNode = document.getElementById("family-status-result");
    resultNode.innerHTML = "";
    try {
      const result = await api("/api/family/reports", { reference, token });
      setMessage(message, "Private report status retrieved.");
      resultNode.innerHTML = `<div class="notice"><strong>${escapeHtml(result.report.reference)}</strong> · ${escapeHtml(result.report.status)}<br>Last updated ${escapeHtml(new Date(result.report.updatedAt).toLocaleString("en-GB"))}</div>
        <h3>Report updates</h3>${result.timeline.map(item => `<p class="muted">${escapeHtml(new Date(item.at).toLocaleString("en-GB"))} · ${escapeHtml(item.status || (item.event === "report_received" ? "Report received" : "Status updated"))}</p>`).join("")}`;
    } catch (error) {
      setMessage(message, error.message, true);
    }
  });
})();
