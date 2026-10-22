"use strict";

/* PROJECTS */

function openProjectForm(id=null){
  $("projectForm").reset();
  $("projectId").value = "";
  $("projectFormTitle").textContent = "ثبت پروژه";
  $("pStatus").value = "فعال";
  $("pType").value = "ایردراپ";
  $("pCost").value = "0";

  if(id){
    const p = state.projects.find(x=>x.id===id);
    if(!p) return;
    $("projectFormTitle").textContent = "ویرایش پروژه";
    $("projectId").value = p.id;
    $("pName").value = p.name || "";
    $("pNetwork").value = p.network || "";
    $("pType").value = p.type || "ایردراپ";
    $("pStatus").value = p.status || "نیازمند بررسی";
    $("pDeadline").value = p.deadline || "";
    $("pCost").value = num(p.cost);
    $("pUrl").value = p.url || "";
    $("pCampaign").value = p.campaign || "";
    $("pNotes").value = p.notes || "";
  }
  openModal("projectModal");
}

$("projectForm").addEventListener("submit",e=>{
  e.preventDefault();
  const id = $("projectId").value;
  const name = $("pName").value.trim();
  if(!name){toast("نام پروژه را وارد کن.");return}

  const url = $("pUrl").value.trim();
  const campaign = $("pCampaign").value.trim();
  if(url && !safeUrl(url)){toast("لینک منبع باید آدرس HTTP یا HTTPS معتبر باشد.");return}
  if(campaign && !safeUrl(campaign)){toast("لینک کمپین معتبر نیست.");return}

  const existing = id ? state.projects.find(p=>p.id===id) : null;
  const duplicate = state.projects.find(p=>
    p.id !== id && p.name.trim().toLowerCase() === name.toLowerCase()
  );
  if(duplicate && !confirm("پروژه‌ای با همین نام وجود دارد. آیا می‌خواهی یک مورد جداگانه ثبت کنی؟")) return;

  const project = {
    id: id || uid(),
    name,
    network: $("pNetwork").value.trim(),
    type: $("pType").value,
    status: $("pStatus").value,
    deadline: $("pDeadline").value,
    cost: Math.max(0,num($("pCost").value)),
    url,
    campaign,
    notes: $("pNotes").value.trim(),
    createdAt: existing?.createdAt || new Date().toISOString(),
    checkedAt: existing?.checkedAt || null,
    updatedAt: new Date().toISOString()
  };

  if(existing) Object.assign(existing,project);
  else state.projects.unshift(project);

  closeModal("projectModal");
  saveState();
  toast("پروژه ذخیره شد.");
});

function statusClass(status){
  if(status==="فعال" || status==="تکمیل‌شده") return "good";
  if(status==="مشکوک" || status==="منقضی") return "bad";
  return "warn";
}

function renderProjects(){
  const query = $("projectSearch").value.trim().toLowerCase();
  const filter = $("projectFilter").value;
  const typeFilter = $("projectTypeFilter").value;

  const projects = state.projects.filter(p=>{
    const haystack = [p.name,p.network,p.notes,p.type].join(" ").toLowerCase();
    return (!query || haystack.includes(query))
      && (!filter || p.status===filter)
      && (!typeFilter || p.type===typeFilter);
  });

  if(!projects.length){
    $("projectTable").innerHTML = '<tr><td colspan="6" class="empty">پروژه‌ای پیدا نشد. می‌توانی اولین فرصت را ثبت کنی.</td></tr>';
    return;
  }

  $("projectTable").innerHTML = projects.map(p=>`
    <tr>
      <td><strong>${escapeHTML(p.name)}</strong><br>
        <span class="muted">${escapeHTML(p.network||"شبکه نامشخص")}</span>
      </td>
      <td>${escapeHTML(p.type||"—")}</td>
      <td><span class="status ${statusClass(p.status)}">${escapeHTML(p.status)}</span></td>
      <td>${faDate(p.deadline)}</td>
      <td>${faDate(p.checkedAt)}</td>
      <td><div class="actions">
        <button class="btn small" onclick="openProjectForm('${p.id}')">ویرایش</button>
        <button class="btn small" onclick="markProjectChecked('${p.id}')">ثبت بررسی</button>
        <button class="btn small danger" onclick="deleteProject('${p.id}')">حذف</button>
      </div></td>
    </tr>
  `).join("");
}

function markProjectChecked(id){
  const p = state.projects.find(x=>x.id===id);
  if(!p) return;
  p.checkedAt = new Date().toISOString();
  saveState();
  toast("زمان بررسی دستی ثبت شد؛ اطلاعات آنلاین بررسی نشده است.");
}

function deleteProject(id){
  const p = state.projects.find(x=>x.id===id);
  if(!p || !confirm("پروژهٔ «"+p.name+"» حذف شود؟")) return;
  state.projects = state.projects.filter(x=>x.id!==id);
  saveState();
  toast("پروژه حذف شد.");
}
