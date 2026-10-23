/* E-Cycle frontend logic. Talks to the Flask API at /api (same origin).
   All user-supplied text is inserted with textContent, never innerHTML,
   so stored data can't inject markup (XSS). */

/* ---------- helpers ---------- */
async function api(path, options = {}) {
    const opts = { method: options.method || "GET", credentials: "same-origin", headers: {} };
    if (options.body !== undefined) {
        opts.headers["Content-Type"] = "application/json";
        opts.body = JSON.stringify(options.body);
    }
    let res;
    try { res = await fetch("/api" + path, opts); }
    catch (e) { throw { message: "Cannot reach the server. Is the backend running?" }; }
    let data = {};
    try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
    if (!res.ok) throw { status: res.status, message: data.error || "Something went wrong", field: data.field };
    return data;
}

function $(id) { return document.getElementById(id); }

function make(tag, text, className) {
    const el = document.createElement(tag);
    if (text !== undefined) el.textContent = text;
    if (className) el.className = className;
    return el;
}

function showMessage(el, text, kind) {
    if (!el) return;
    el.textContent = text;
    el.style.color = kind === "ok" ? "#16804b" : "#b3261e";
    el.style.fontWeight = "600";
    el.setAttribute("role", "status");
    el.setAttribute("aria-live", "polite");
}

async function withBusy(event, work) {
    event.preventDefault();
    const btn = event.target.querySelector("button[type=submit]");
    if (btn) btn.disabled = true;
    try { await work(); } finally { if (btn) btn.disabled = false; }
}

function prettyStatus(s) { return s.replace(/_/g, " "); }
function prettyCondition(c) {
    return c.split("_").map(w => w[0].toUpperCase() + w.slice(1)).join(" ");
}
function prettyDate(iso) {
    const d = new Date(iso.length === 10 ? iso + "T00:00:00" : iso);
    return d.toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" });
}
function badge(text) { return make("span", text, "badge"); }

/* One shared assistant surface. It is deliberately server-backed; if Gemini
   is not configured the API returns a truthful setup/unavailable message. */
function mountAssistant() {
    if (document.querySelector(".ecycle-assistant")) return;
    const launcher = make("button", "E-Cycle AI", "ecycle-assistant");
    launcher.type = "button"; launcher.setAttribute("aria-expanded", "false");
    const panel = make("section", undefined, "assistant-panel"); panel.hidden = true;
    const title = make("strong", "E-Cycle AI");
    const close = make("button", "×", "assistant-close"); close.type = "button";
    const header = make("div", undefined, "assistant-header"); header.append(title, close);
    const messages = make("div", undefined, "assistant-messages");
    messages.append(make("p", "Ask about safe disposal, submissions, or the recycling lifecycle."));
    const form = make("form", undefined, "assistant-form");
    const input = make("input"); input.placeholder = "Ask E-Cycle AI…"; input.maxLength = 4000; input.required = true;
    const send = make("button", "Send", "btn btn-primary"); send.type = "submit"; form.append(input, send);
    panel.append(header, messages, form); document.body.append(launcher, panel);
    const toggle = () => { panel.hidden = !panel.hidden; launcher.setAttribute("aria-expanded", String(!panel.hidden)); if (!panel.hidden) input.focus(); };
    launcher.onclick = toggle; close.onclick = toggle;
    form.onsubmit = async (event) => { event.preventDefault(); const text = input.value.trim(); if (!text) return; input.value = ""; messages.append(make("p", `You: ${text}`)); send.disabled = true;
        try { const r = await api("/assistant/chat", { method: "POST", body: { message: text } }); messages.append(make("p", r.message, r.available ? "assistant-ok" : "assistant-warning")); }
        catch (e) { messages.append(make("p", e.message, "assistant-warning")); } finally { send.disabled = false; input.focus(); }
    };
}

let currentUser = null;

/* ---------- navbar: reflect login state on every page ---------- */
async function initNav() {
    const box = document.querySelector(".nav-buttons");
    const links = document.querySelector(".nav-links");
    try { currentUser = (await api("/auth/me")).user; } catch (e) { currentUser = null; }
    if (!box || !currentUser) return;
    box.textContent = "";
    const dash = make("a", "Dashboard", "btn btn-outline"); dash.href = "dashboard.html";
    const schedule = make("a", "Schedule Pickup", "btn btn-outline"); schedule.href = "operations.html";
    const out = make("button", "Logout", "btn btn-primary");
    out.type = "button";
    out.onclick = async () => {
        out.disabled = true;
        try {
            await api("/auth/logout", { method: "POST", body: {} });
            window.location.href = "index.html";
        } catch (e) {
            out.disabled = false;
            const status = document.querySelector("main") || document.body;
            let msg = $("navMessage");
            if (!msg) { msg = make("p", undefined, "form-message"); msg.id = "navMessage"; status.prepend(msg); }
            showMessage(msg, e.message);
        }
    };
    box.append(dash, schedule, out);
    if (currentUser.role === "admin" && links) {
        const a = make("a", "Admin"); a.href = "admin.html"; links.append(a);
    }
}

/* ---------- distributor workspace ---------- */
async function loadDistributorWorkspace() {
    const rows = $("distributorRows");
    if (!rows) return;
    try {
        const result = await api("/distributor/jobs");
        rows.textContent = "";
        if (!result.jobs.length) { const td = make("td", "No assignments are currently available.", "empty"); td.colSpan = 6; const tr = make("tr"); tr.append(td); rows.append(tr); return; }
        result.jobs.forEach(job => {
            const tr = make("tr");
            [job.tracking_id, `${job.quantity} × ${job.device_name}`, `${job.pickup_date} ${job.start_time}–${job.end_time}`, job.location, prettyStatus(job.status)].forEach(value => tr.append(make("td", value)));
            const td = make("td");
            if (job.status === "OFFERED") {
                const accept = make("button", "Accept", "btn btn-primary"); accept.type = "button"; accept.onclick = () => decideDistributorJob(job.id, "ACCEPTED");
                const decline = make("button", "Decline", "btn btn-outline"); decline.type = "button"; decline.style.marginLeft = "6px"; decline.onclick = () => decideDistributorJob(job.id, "DECLINED"); td.append(accept, decline);
            } else if (job.status === "ACCEPTED") {
                const complete = make("button", "Record collection", "btn btn-primary"); complete.type = "button"; complete.onclick = () => completeDistributorJob(job.id, job.quantity); td.append(complete);
            } else td.append(make("span", "—"));
            tr.append(td); rows.append(tr);
        });
    } catch (e) { showMessage($("distributorMessage"), e.message); }
}

async function decideDistributorJob(id, decision) {
    const reason = decision === "DECLINED" ? window.prompt("Why are you declining this assignment?") : "";
    if (decision === "DECLINED" && !reason) return;
    try { await api(`/distributor/assignments/${id}/decision`, { method: "POST", body: { decision, reason } }); loadDistributorWorkspace(); }
    catch (e) { showMessage($("distributorMessage"), e.message); }
}

async function completeDistributorJob(id, quantity) {
    const note = window.prompt("Enter collection evidence or acknowledgement details:");
    if (!note) return;
    try { await api(`/distributor/assignments/${id}/complete`, { method: "POST", body: { collected_quantity: quantity, evidence_note: note } }); loadDistributorWorkspace(); }
    catch (e) { showMessage($("distributorMessage"), e.message); }
}

/* ---------- auth forms ---------- */
function handleLogin(event) {
    withBusy(event, async () => {
        const msg = $("loginMessage");
        try {
            await api("/auth/login", { method: "POST", body: { email: $("loginEmail").value, password: $("loginPassword").value } });
            window.location.href = "dashboard.html";
        } catch (e) { showMessage(msg, e.message); }
    });
}

function handleRegister(event) {
    withBusy(event, async () => {
        const msg = $("registerMessage");
        try {
            await api("/auth/register", { method: "POST", body: {
                name: $("regName").value, phone: $("regPhone").value, email: $("regEmail").value,
                password: $("regPassword").value, address: $("regAddress").value } });
            msg.textContent = "";
            msg.append(badge("Account created"), " ");
            const a = make("a", "Login now →"); a.href = "login.html";
            a.style.cssText = "color:#16804b;font-weight:700";
            msg.append(a);
            event.target.reset();
        } catch (e) { showMessage(msg, e.message); }
    });
}

/* ---------- submit e-waste ---------- */
function handleSubmitEwaste(event) {
    withBusy(event, async () => {
        const msg = $("submitMessage");
        showMessage(msg, "");
        try {
            const r = await api("/submissions", { method: "POST", body: {
                category: $("category").value, device_name: $("device").value, brand: $("brand").value,
                quantity: parseInt($("quantity").value, 10), condition: $("condition").value,
                battery_damaged: $("batteryDamaged").checked,
                location: $("location").value, description: $("description").value } });
            $("trackingId").textContent = r.tracking_id;
            $("recommendation").textContent = r.recommendation;
            $("guestNote").style.display = r.linked_to_account ? "none" : "block";
            $("trackLink").href = "track.html?id=" + encodeURIComponent(r.tracking_id);
            $("submissionResult").classList.add("show");
            $("submissionResult").scrollIntoView({ behavior: "smooth" });
            event.target.reset();
        } catch (e) { showMessage(msg, e.message); }
    });
}

/* ---------- track ---------- */
async function runTrack(id) {
    const msg = $("trackMessage"), result = $("trackResult");
    showMessage(msg, "");
    result.classList.remove("show");
    try {
        const t = await api("/track/" + encodeURIComponent(id));
        $("shownTrackId").textContent = t.tracking_id;
        $("trackSummary").textContent = `${t.quantity} × ${t.device_name} (${t.category}) — ${t.recommendation}`;
        const box = $("timeline");
        box.textContent = "";
        t.stages.forEach(s => {
            const row = make("div", undefined, "status-line");
            const dot = make("span", undefined, "dot");
            if (!s.done) dot.style.background = "#ccd8d0";
            const info = make("div");
            info.append(make("strong", s.label), document.createElement("br"),
                make("small", s.done && s.at ? `${s.description} (${prettyDate(s.at)})` : "Pending"));
            row.append(dot, info);
            box.append(row);
        });
        const historyBox = $("trackHistory");
        if (historyBox) {
            historyBox.textContent = "";
            (t.history || []).forEach(item => {
                const row = make("div", undefined, "guide-item");
                row.style.marginTop = "10px";
                row.append(make("strong", prettyStatus(item.status)),
                    make("p", item.note || "Status updated."),
                    make("small", item.at ? new Date(item.at).toLocaleString() : "Time unavailable"));
                historyBox.append(row);
            });
        }
        result.classList.add("show");
        result.scrollIntoView({ behavior: "smooth" });
    } catch (e) { showMessage(msg, e.message); }
}

function handleTrack(event) {
    withBusy(event, async () => {
        const id = $("trackId").value.trim().toUpperCase();
        if (id) await runTrack(id);
    });
}

/* ---------- dashboard ---------- */
async function loadDashboard() {
    try {
        const d = await api("/submissions/mine");
        $("welcomeName").textContent = currentUser.name.split(" ")[0];
        $("statTotal").textContent = d.stats.total;
        $("statActive").textContent = d.stats.active;
        $("statCompleted").textContent = d.stats.completed;
        $("statCertificates").textContent = d.stats.certificates;
        const body = $("submissionRows");
        body.textContent = "";
        if (!d.submissions.length) {
            const tr = make("tr"), td = make("td", "No submissions yet. Use “Submit E-Waste” to add your first one.", "empty");
            td.colSpan = 5; tr.append(td); body.append(tr);
            return;
        }
        d.submissions.forEach(s => {
            const tr = make("tr");
            const track = make("a", s.tracking_id); track.href = "track.html?id=" + encodeURIComponent(s.tracking_id);
            track.style.cssText = "color:#16804b;font-weight:700";
            const tdTrack = make("td"); tdTrack.append(track);
            const tdStatus = make("td"); tdStatus.append(badge(prettyStatus(s.status)));
            tr.append(make("td", s.device_name), make("td", prettyCondition(s.device_condition)),
                make("td", s.recommendation), tdStatus, tdTrack);
            body.append(tr);
        });
    } catch (e) {
        if (e.status === 401) { window.location.href = "login.html"; return; }
        showMessage($("dashboardMessage"), e.message);
    }
}

/* ---------- community drives ---------- */
async function loadDrives() {
    const list = $("driveList");
    try {
        const { drives } = await api("/drives");
        list.textContent = "";
        drives.forEach(d => {
            const card = make("div", undefined, "info-card");
            card.append(badge(d.status), make("h3", d.title));
            const loc = make("p"); loc.append(make("strong", "Location: "), d.location);
            const when = make("p"); when.append(make("strong", "Date: "), prettyDate(d.drive_date));
            const who = make("p"); who.append(make("strong", "Participants: "), String(d.participants));
            card.append(loc, when, who);
            if (d.description) card.append(make("p", d.description));
            if (d.status === "UPCOMING") {
                let btn;
                if (!currentUser) { btn = make("a", "Login to Join", "btn btn-primary"); btn.href = "login.html"; }
                else if (d.joined) { btn = make("span", "Joined ✓", "badge"); }
                else {
                    btn = make("button", "Join Drive", "btn btn-primary"); btn.type = "button";
                    btn.onclick = async () => {
                        btn.disabled = true;
                        try { await api(`/drives/${d.id}/join`, { method: "POST", body: {} }); await loadDrives(); }
                        catch (e) { btn.disabled = false; showMessage($("driveMessage"), e.message); }
                    };
                }
                btn.style.marginTop = "15px";
                card.append(btn);
            }
            list.append(card);
        });
        if (!drives.length) list.append(make("p", "No drives scheduled yet.", "empty"));
    } catch (e) { showMessage($("driveMessage"), e.message); }
}

/* ---------- impact ---------- */
async function loadImpact() {
    try {
        const d = await api("/impact");
        $("impTotal").textContent = d.total_submissions;
        $("impCollected").textContent = d.collected_items;
        $("impParticipants").textContent = d.community_participants;
        $("impDrives").textContent = d.completed_drives;
        const n = d.distribution;
        const count = k => n[k] + (n[k] === 1 ? " submission" : " submissions");
        $("distReuse").textContent = count("reuse");
        $("distRepair").textContent = count("repair");
        $("distRecycle").textContent = count("recycle");
        $("distSpecialized").textContent = count("specialized");
    } catch (e) { showMessage($("impactMessage"), e.message); }
}

/* ---------- admin ---------- */
async function loadAdmin() {
    const rows = $("adminRows"), msg = $("adminMessage");
    if (!rows) return;
    try {
        if (!currentUser) { window.location.href = "login.html"; return; }
        const filter = $("adminStatusFilter")?.value || "";
        const query = filter ? "?status=" + encodeURIComponent(filter) : "";
        const { submissions } = await api("/admin/submissions" + query);
        rows.textContent = "";
        if (!submissions.length) {
            const tr = make("tr"), td = make("td", "No submissions match this filter.", "empty");
            td.colSpan = 6; tr.append(td); rows.append(tr);
        }
        submissions.forEach(s => {
            const tr = make("tr"), tdStatus = make("td");
            tdStatus.append(badge(prettyStatus(s.status)));
            const tdAct = make("td");
            if (s.next_status) {
                const b = make("button", "Mark " + prettyStatus(s.next_status), "btn btn-light");
                b.type = "button";
                b.onclick = async () => {
                    const note = window.prompt("Optional update note (leave blank for the default note):", "");
                    if (note === null) return;
                    b.disabled = true;
                    try {
                        await api(`/admin/submissions/${encodeURIComponent(s.tracking_id)}/status`,
                            { method: "PATCH", body: { status: s.next_status, note: note.trim() || undefined } });
                        showMessage(msg, `${s.tracking_id} updated to ${prettyStatus(s.next_status)}.`, "ok");
                        await loadAdmin();
                    } catch (e) { b.disabled = false; showMessage(msg, e.message); }
                };
                tdAct.append(b);
            } else tdAct.append("Final");
            tr.append(make("td", s.tracking_id), make("td", `${s.quantity} × ${s.device_name}`),
                make("td", s.recommendation), make("td", s.owner_email || "Guest"), tdStatus, tdAct);
            rows.append(tr);
        });
    } catch (e) {
        if (e.status === 401) window.location.href = "login.html";
        else showMessage(msg, e.status === 403 ? "Admin access required." : e.message);
    }
}

async function handleAdminCreateDrive(event) {
    await withBusy(event, async () => {
        const msg = $("driveCreateMessage");
        try {
            const result = await api("/admin/drives", { method: "POST", body: {
                title: $("driveTitle").value,
                drive_date: $("driveDate").value,
                location: $("driveLocation").value,
                description: $("driveDescription").value
            }});
            showMessage(msg, `Community drive created (ID ${result.id}).`, "ok");
            $("driveCreateForm").reset();
        } catch (e) { showMessage(msg, e.message); }
    });
}

async function handleAdminCreateSlot(event) { await withBusy(event, async () => { try { const r = await api("/admin/pickup-slots", { method: "POST", body: { partner_name: $("slotPartner").value, service_area: $("slotArea").value, slot_date: $("slotDate").value, start_time: $("slotStart").value, end_time: $("slotEnd").value, capacity: parseInt($("slotCapacity").value, 10) } }); showMessage($("slotMessage"), `Pickup slot created (ID ${r.id}).`, "ok"); event.target.reset(); } catch (e) { showMessage($("slotMessage"), e.message); } }); }
async function handleAdminIssueCertificate(event) { await withBusy(event, async () => { try { const r = await api("/admin/certificates", { method: "POST", body: { tracking_id: $("certificateTracking").value } }); showMessage($("certificateMessage"), `Issued ${r.certificate_no}. Verification token: ${r.verification_token}`, "ok"); event.target.reset(); } catch (e) { showMessage($("certificateMessage"), e.message); } }); }

async function loadAdminReports() {
    try { const q = new URLSearchParams(); if ($("reportStatusFilter").value) q.set("status", $("reportStatusFilter").value); if ($("reportSeverityFilter").value) q.set("severity", $("reportSeverityFilter").value); const data = await api("/admin/reports" + (q.toString() ? "?" + q : "")); const rows = $("reportRows"); rows.textContent = ""; if (!data.reports.length) { const tr = make("tr"), td = make("td", "No reports match these filters.", "empty"); td.colSpan = 5; tr.append(td); rows.append(tr); return; } data.reports.forEach(r => { const tr = make("tr"); tr.append(make("td", r.report_id + " — " + r.title), make("td", r.issue_type), make("td", r.severity), make("td", r.status)); const td = make("td"), select = document.createElement("select"); ["SUBMITTED","UNDER_REVIEW","INVESTIGATING","RESOLVED","FALSE_POSITIVE"].forEach(s => { const o = make("option", s); o.value = s; o.selected = s === r.status; select.append(o); }); const button = make("button", "Save", "btn btn-outline"); button.type = "button"; button.onclick = async () => { button.disabled = true; try { await api("/admin/reports/" + encodeURIComponent(r.report_id), { method: "PATCH", body: { status: select.value } }); showMessage($("reportAdminMessage"), "Report updated.", "ok"); await loadAdminReports(); } catch (e) { button.disabled = false; showMessage($("reportAdminMessage"), e.message); } }; td.append(select, button); tr.append(td); rows.append(tr); }); } catch (e) { showMessage($("reportAdminMessage"), e.message); }
}
async function loadAuditLogs() { try { const data = await api("/admin/audit-logs?limit=100"), rows = $("auditRows"); rows.textContent = ""; if (!data.logs.length) { const tr = make("tr"), td = make("td", "No audit events yet.", "empty"); td.colSpan = 4; tr.append(td); rows.append(tr); return; } data.logs.forEach(x => { const tr = make("tr"); tr.append(make("td", prettyDate(x.created_at)), make("td", x.actor_email || "system"), make("td", x.action), make("td", `${x.entity_type}:${x.entity_id}`)); rows.append(tr); }); } catch (e) { showMessage($("auditMessage"), e.message); } }

async function loadOperations() {
    try {
        const [slots, mine] = await Promise.all([api("/pickup-slots"), api("/submissions/mine")]);
        const select = $("pickupSubmission"); select.textContent = "";
        mine.submissions.filter(s => ["SUBMITTED", "VERIFIED"].includes(s.status)).forEach(s => { const option = make("option", `${s.tracking_id} — ${s.device_name}`); option.value = s.tracking_id; select.append(option); });
        const list = $("pickupSlots"); list.textContent = "";
        if (!slots.slots.length) list.append(make("p", "No pickup slots are currently available."));
        slots.slots.forEach(s => { const row = make("div", undefined, "guide-item"); row.append(make("strong", `${prettyDate(s.slot_date)} · ${s.start_time}–${s.end_time}`), make("p", `${s.partner_name} · ${s.service_area} · ${s.capacity - s.booked} places left`)); const button = make("button", "Book this slot", "btn btn-primary"); button.type = "button"; button.onclick = async () => { button.disabled = true; try { const result = await api("/pickups", { method: "POST", body: { slot_id: s.id, tracking_id: select.value } }); showMessage($("pickupMessage"), `Pickup confirmed for ${result.tracking_id}.`, "ok"); await loadOperations(); } catch (e) { button.disabled = false; showMessage($("pickupMessage"), e.message); } }; row.append(button); list.append(row); });
        const pickups = (await api("/pickups/mine")).pickups, pickupBox = $("myPickups"); pickupBox.textContent = ""; if (!pickups.length) pickupBox.append(make("p", "No pickups booked yet.")); pickups.forEach(p => pickupBox.append(make("p", `${p.tracking_id} · ${prettyDate(p.slot_date)} ${p.start_time}–${p.end_time} · ${p.status}`)));
        const certs = (await api("/certificates/mine")).certificates, certBox = $("myCertificates"); certBox.textContent = ""; if (!certs.length) certBox.append(make("p", "Certificates appear here after processing.")); certs.forEach(c => { const a = make("a", `${c.certificate_no} · ${c.device_name}`); a.href = `/certificate.html?token=${encodeURIComponent(c.verification_token)}`; const p = make("p"); p.append(a); certBox.append(p); });
    } catch (e) { if (e.status === 401) window.location.href = "login.html"; else showMessage($("pickupMessage"), e.message); }
}

/* ---------- page bootstrap ---------- */
document.addEventListener("DOMContentLoaded", async () => {
    mountAssistant();
    await initNav();
    if ($("submissionRows")) loadDashboard();
    if ($("driveList")) loadDrives();
    if ($("impTotal")) loadImpact();
    if ($("adminRows")) {
        loadAdmin();
        $("adminStatusFilter")?.addEventListener("change", loadAdmin);
        $("adminRefresh")?.addEventListener("click", loadAdmin);
        const dateInput = $("driveDate");
        if (dateInput) dateInput.min = new Date().toISOString().slice(0, 10);
    }
    if ($("reportRows")) { loadAdminReports(); $("reportStatusFilter").addEventListener("change", loadAdminReports); $("reportSeverityFilter").addEventListener("change", loadAdminReports); }
    if ($("auditRows")) loadAuditLogs();
    if ($("trackResult")) {
        const id = new URLSearchParams(window.location.search).get("id");
        if (id) { $("trackId").value = id; runTrack(id.trim().toUpperCase()); }
    }
    if ($("pickupSlots")) loadOperations();
    if ($("distributorRows")) {
        $("distributorRefresh")?.addEventListener("click", loadDistributorWorkspace);
        loadDistributorWorkspace();
    }
});
