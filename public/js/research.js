"use strict";

/*
 Research page: sends the form to POST /api/research, reads the NDJSON stream
 (stage | source | result | error), renders the report and keeps a local history.
*/

const RESEARCH_HISTORY_KEY = "CryptoHunterAI_research_v1";
const RESEARCH_HISTORY_MAX = 20;
const RESEARCH_TIMEOUT_MS = 150000;
const SOURCE_LABELS = { website: "وب‌سایت رسمی", coingecko: "CoinGecko", github: "GitHub" };

let currentReport = null;

// Splits a streaming buffer into complete JSON events and the unfinished rest.
function splitNdjson(buffer){
  const parts = buffer.split("\n");
  const rest = parts.pop();
  const events = [];
  for(const line of parts){
    if(!line.trim()) continue;
    try{ events.push(JSON.parse(line)); }catch(e){ /* ignore a corrupt line */ }
  }
  return { events, rest };
}

function buildReportHtml(markdown, title){
  return '<!doctype html><html lang="fa" dir="rtl"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width,initial-scale=1">' +
    "<title>" + escapeHTML(title) + "</title>" +
    "<style>body{font-family:Tahoma,Arial,sans-serif;max-width:850px;margin:24px auto;padding:0 16px;line-height:1.9;color:#111}" +
    "table{border-collapse:collapse;width:100%;font-size:13px}th,td{border:1px solid #ccc;padding:6px 8px;text-align:right}" +
    "code{direction:ltr;unicode-bidi:plaintext}.tablewrap{overflow:auto}</style></head><body>" +
    renderMarkdown(markdown) + "</body></html>";
}

function reportFileName(report, ext){
  const base = (report.input.name || "report").replace(/[^\p{L}\p{N}_-]+/gu, "-").slice(0, 40) || "report";
  return "CryptoHunterAI-" + base + "-" + report.generatedAt.slice(0, 10) + "." + ext;
}

// ---------- history (localStorage; the page works without it) ----------
function loadResearchHistory(){
  try{
    const list = JSON.parse(localStorage.getItem(RESEARCH_HISTORY_KEY) || "[]");
    return Array.isArray(list) ? list : [];
  }catch(e){ return []; }
}

function saveResearchHistory(report){
  const entry = {
    id: uid(),
    title: report.input.name || report.input.url || report.input.contract,
    createdAt: report.generatedAt,
    riskLevel: report.risk.level,
    report
  };
  const list = [entry, ...loadResearchHistory()].slice(0, RESEARCH_HISTORY_MAX);
  try{ localStorage.setItem(RESEARCH_HISTORY_KEY, JSON.stringify(list)); }
  catch(e){ toast("ذخیرهٔ تاریخچه در مرورگر ممکن نشد (فضا یا دسترسی)."); }
  renderResearchHistory();
}

function renderResearchHistory(){
  const list = loadResearchHistory();
  $("researchHistory").innerHTML = list.length
    ? list.map(e => `<div class="toolbar">
        <div style="flex:1;min-width:150px"><strong>${escapeHTML(e.title)}</strong>
        <div class="muted">${escapeHTML(faDate(e.createdAt))} — ${escapeHTML(e.riskLevel)}</div></div>
        <button class="btn small" onclick="openResearchHistory('${escapeHTML(e.id)}')">نمایش</button>
        <button class="btn small danger" onclick="deleteResearchHistory('${escapeHTML(e.id)}')">حذف</button>
      </div>`).join("")
    : '<div class="empty">هنوز تحقیقی انجام نشده است.</div>';
}

function openResearchHistory(id){
  const e = loadResearchHistory().find(x => x.id === id);
  if(e) showResearchReport(e.report);
}

function deleteResearchHistory(id){
  try{ localStorage.setItem(RESEARCH_HISTORY_KEY, JSON.stringify(loadResearchHistory().filter(x => x.id !== id))); }
  catch(e){ /* nothing to do */ }
  renderResearchHistory();
}

// ---------- UI state ----------
function showResearchReport(report){
  currentReport = report;
  $("researchReport").innerHTML = renderMarkdown(report.markdown);
  $("researchResultCard").classList.remove("hidden");
  $("researchResultCard").scrollIntoView({ behavior: "smooth", block: "start" });
}

function showResearchError(message, sources){
  const failed = (sources || []).filter(s => !s.ok)
    .map(s => `<li>${escapeHTML(SOURCE_LABELS[s.id] || s.id)}: ${escapeHTML(s.error?.message || "ناموفق")}</li>`).join("");
  $("researchError").innerHTML = `<strong>${escapeHTML(message)}</strong>` + (failed ? `<ul>${failed}</ul>` : "");
  $("researchError").classList.remove("hidden");
}

function addResearchStep(text, ok){
  const li = document.createElement("li");
  li.textContent = (ok === false ? "✗ " : ok === true ? "✓ " : "• ") + text;
  $("researchSteps").appendChild(li);
}

function handleResearchEvent(ev, state){
  if(ev.type === "stage"){
    $("researchStage").textContent = ev.message;
  }else if(ev.type === "source"){
    addResearchStep((SOURCE_LABELS[ev.id] || ev.id) + ": " + (ev.ok ? "دریافت شد" : "ناموفق"), ev.ok);
  }else if(ev.type === "result"){
    state.done = true;
    $("researchStage").textContent = "تحقیق کامل شد.";
    showResearchReport(ev.report);
    saveResearchHistory(ev.report);
  }else if(ev.type === "error"){
    state.done = true;
    $("researchStage").textContent = "تحقیق ناموفق بود.";
    showResearchError(ev.error?.message || "خطای نامشخص", ev.sources);
  }
}

async function startResearch(event){
  event.preventDefault();
  const btn = $("researchBtn");
  const body = {
    name: $("rName").value, url: $("rUrl").value, chain: $("rChain").value,
    contract: $("rContract").value, question: $("rQuestion").value
  };
  const headers = { "content-type": "application/json" };
  const token = $("rToken").value.trim();
  if(token){
    headers.authorization = "Bearer " + token;
    try{ sessionStorage.setItem("CryptoHunterAI_token", token); }catch(e){ /* optional */ }
  }

  btn.disabled = true;
  $("researchError").classList.add("hidden");
  $("researchResultCard").classList.add("hidden");
  $("researchSteps").innerHTML = "";
  $("researchProgressCard").classList.remove("hidden");
  $("researchStage").textContent = "در حال ارسال درخواست…";

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), RESEARCH_TIMEOUT_MS);
  const state = { done: false };
  try{
    const res = await fetch("/api/research", { method: "POST", headers, body: JSON.stringify(body), signal: controller.signal });
    if(!res.ok){
      let message = "خطای سرور (" + res.status + ")";
      try{ message = (await res.json()).error?.message || message; }catch(e){ /* keep default */ }
      $("researchStage").textContent = "درخواست رد شد.";
      showResearchError(message);
      return;
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for(;;){
      const { done, value } = await reader.read();
      if(done) break;
      buffer += decoder.decode(value, { stream: true });
      const parsed = splitNdjson(buffer);
      buffer = parsed.rest;
      parsed.events.forEach(ev => handleResearchEvent(ev, state));
    }
    splitNdjson(buffer + "\n").events.forEach(ev => handleResearchEvent(ev, state));
    if(!state.done){
      $("researchStage").textContent = "اتصال قبل از پایان تحقیق قطع شد.";
      showResearchError("پاسخ ناقص بود؛ دوباره تلاش کنید.");
    }
  }catch(err){
    $("researchStage").textContent = "ارتباط با سرور ناموفق بود.";
    showResearchError(err.name === "AbortError" ? "زمان انتظار تمام شد." : "ارتباط با سرور برقرار نشد. آیا برنامه روی Cloudflare اجرا می‌شود؟");
  }finally{
    clearTimeout(timer);
    btn.disabled = false;
  }
}

function downloadResearchMarkdown(){
  if(currentReport) downloadBlob(currentReport.markdown, reportFileName(currentReport, "md"), "text/markdown;charset=utf-8");
}

function downloadResearchHtml(){
  if(currentReport) downloadBlob(buildReportHtml(currentReport.markdown, "گزارش " + (currentReport.input.name || "")), reportFileName(currentReport, "html"), "text/html;charset=utf-8");
}

function copyResearchMarkdown(){
  if(!currentReport) return;
  if(navigator.clipboard?.writeText){
    navigator.clipboard.writeText(currentReport.markdown).then(() => toast("گزارش کپی شد."), () => fallbackCopy(currentReport.markdown));
  }else{
    fallbackCopy(currentReport.markdown);
  }
}

async function checkApiHealth(){
  const badge = $("connectionStatus");
  try{
    const res = await fetch("/api/health");
    const h = await res.json();
    $("tokenField").classList.toggle("hidden", !h.accessTokenRequired);
    $("publicWarning").classList.toggle("hidden", Boolean(h.accessTokenRequired));
    $("tokenMissing").classList.toggle("hidden", !(h.accessTokenRequired && !h.tokenConfigured));
    badge.textContent = h.aiBinding ? "هوش مصنوعی متصل" : "نیازمند تنظیم هوش مصنوعی";
    badge.className = "status " + (h.aiBinding ? "good" : "warn");
  }catch(e){
    badge.textContent = "API در دسترس نیست (حالت محلی)";
    badge.className = "status bad";
  }
}

function initResearch(){
  try{ $("rToken").value = sessionStorage.getItem("CryptoHunterAI_token") || ""; }catch(e){ /* optional */ }
  renderResearchHistory();
  checkApiHealth();
}

if(typeof document !== "undefined" && document.getElementById("researchForm")) initResearch();
