"use strict";

/* DASHBOARD & REPORTS */

function totals(){
  let value=0,cost=0,realized=0,unrealized=0,count=0,hasUnrealized=false;

  for(const a of state.assets){
    const s=getAssetStats(a);
    value+=s.value;
    cost+=s.cost;
    realized+=s.realized;
    if(s.unrealized!==null){unrealized+=s.unrealized;hasUnrealized=true}
    if(s.quantity>0) count++;
  }
  return {value,cost,realized,unrealized,count,hasUnrealized};
}

function updateDashboard(){
  const t=totals();
  $("metricProjects").textContent=fmt(state.projects.length,0);
  $("metricActive").textContent=fmt(state.projects.filter(p=>p.status==="فعال").length,0);
  $("metricAssets").textContent=fmt(t.count,0);
  $("metricValue").textContent=fmt(t.value);
  $("metricRealized").textContent=fmt(t.realized);
  $("metricUnrealized").textContent=t.hasUnrealized?fmt(t.unrealized):"نامشخص";
  $("metricDeadlines").textContent=fmt(state.projects.filter(p=>{
    if(!p.deadline || p.status==="منقضی" || p.status==="تکمیل‌شده") return false;
    const days=(new Date(p.deadline+"T23:59:59")-new Date())/86400000;
    return days>=0 && days<=7;
  }).length,0);
  $("lastUpdated").textContent=state.updatedAt ? faDate(state.updatedAt) : "هنوز ثبت نشده";

  const recent=state.projects.slice().sort((a,b)=>
    String(b.updatedAt||b.createdAt).localeCompare(String(a.updatedAt||a.createdAt))
  ).slice(0,5);

  $("dashboardProjects").innerHTML=recent.length ? recent.map(p=>`
    <div style="display:flex;justify-content:space-between;gap:10px;align-items:center;border-bottom:1px solid var(--line);padding:10px 0">
      <div><strong>${escapeHTML(p.name)}</strong><div class="muted">${escapeHTML(p.type)} · مهلت: ${faDate(p.deadline)}</div></div>
      <span class="status ${statusClass(p.status)}">${escapeHTML(p.status)}</span>
    </div>
  `).join("") : '<div class="empty">هنوز پروژه‌ای ثبت نکرده‌ای.</div>';

  const active=state.projects.filter(p=>p.status==="فعال").length;
  const review=state.projects.filter(p=>p.status==="نیازمند بررسی" || p.status==="مشکوک").length;
  const deadline=Number($("metricDeadlines").textContent.replace(/,/g,""))||0;
  $("dashboardMessages").innerHTML=
    `فرصت فعال: <strong>${active}</strong><br>`+
    `پروژهٔ نیازمند بررسی: <strong>${review}</strong><br>`+
    `مهلت نزدیک: <strong>${deadline}</strong><br>`+
    `قیمت‌ها به‌صورت آنلاین بررسی نشده‌اند و هیچ هشدار خودکاری فعال نیست.`;
}

function generateReport(){
  const t=totals();
  const now=new Date();
  const lines=[
    "گزارش CryptoHunterAI",
    "زمان تهیه: "+now.toLocaleString("fa-IR"),
    "",
    "پروژه‌ها: "+state.projects.length,
    "فرصت فعال: "+state.projects.filter(p=>p.status==="فعال").length,
    "نیازمند بررسی یا مشکوک: "+state.projects.filter(p=>p.status==="نیازمند بررسی"||p.status==="مشکوک").length,
    "مهلت نزدیک: "+state.projects.filter(p=>{
      if(!p.deadline||p.status==="منقضی"||p.status==="تکمیل‌شده") return false;
      const days=(new Date(p.deadline+"T23:59:59")-now)/86400000;
      return days>=0&&days<=7;
    }).length,
    "",
    "ارزش تخمینی سبد: $"+fmt(t.value),
    "بهای تمام‌شدهٔ موجودی قابل محاسبه: $"+fmt(t.cost),
    "سود و زیان تحقق‌یافته: $"+fmt(t.realized),
    "سود و زیان تحقق‌نیافته: "+(t.hasUnrealized?"$"+fmt(t.unrealized):"نامشخص"),
    "",
    "محدودیت‌ها:",
    "- اطلاعات بازار آنلاین دریافت نشده است.",
    "- گزارش فقط از اطلاعات محلی ثبت‌شده استفاده می‌کند.",
    "- ارزش پاداش دریافت‌نشده محاسبه نشده است.",
    "- دقت محاسبات به کامل بودن تراکنش‌های واردشده وابسته است."
  ];
  const report={id:uid(),date:now.toISOString(),text:lines.join("\n")};
  state.reports.unshift(report);
  state.reports=state.reports.slice(0,50);
  saveState();
  renderReport();
  toast("گزارش ساخته شد.");
}

function renderReport(){
  const r=state.reports[0];
  $("reportDate").textContent=r?"آخرین گزارش: "+faDate(r.date):"گزارشی ساخته نشده است.";
  $("reportOutput").textContent=r?r.text:"برای ساخت گزارش روی دکمهٔ بالای صفحه بزن.";
}

function copyReport(){
  const text=$("reportOutput").textContent;
  if(!text){toast("گزارشی برای کپی وجود ندارد.");return}
  if(navigator.clipboard && window.isSecureContext){
    navigator.clipboard.writeText(text).then(()=>toast("گزارش کپی شد.")).catch(()=>fallbackCopy(text));
  }else fallbackCopy(text);
}

function fallbackCopy(text){
  const area=document.createElement("textarea");
  area.value=text;document.body.appendChild(area);area.select();
  try{document.execCommand("copy");toast("گزارش کپی شد.")}catch(e){toast("کپی خودکار ممکن نشد. متن را دستی انتخاب کن.")}
  area.remove();
}

function downloadReport(){
  const text=$("reportOutput").textContent;
  if(!text){toast("گزارشی برای ذخیره وجود ندارد.");return}
  downloadBlob(text,"CryptoHunterAI_Report.txt","text/plain;charset=utf-8");
}
