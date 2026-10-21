"use strict";

function loadState(){
  try{
    const raw = localStorage.getItem(STORAGE_KEY);
    if(raw){
      const parsed = JSON.parse(raw);
      state = {
        ...defaultState(),
        ...parsed,
        projects: Array.isArray(parsed.projects) ? parsed.projects : [],
        assets: Array.isArray(parsed.assets) ? parsed.assets : [],
        transactions: Array.isArray(parsed.transactions) ? parsed.transactions : [],
        reports: Array.isArray(parsed.reports) ? parsed.reports : []
      };
    }else{
      // One-time migration from the first prototype, if it exists.
      const old = localStorage.getItem("CryptoHunterAI_v1");
      if(old){
        const parsed = JSON.parse(old);
        const oldProjects = Array.isArray(parsed.projects) ? parsed.projects : [];
        state.projects = oldProjects.map(p => ({
          id: p.id || uid(),
          name: p.name || p.title || "پروژه",
          network: p.network || "",
          type: p.type || "ایردراپ",
          status: p.status || "نیازمند بررسی",
          deadline: p.deadline || "",
          cost: num(p.cost),
          url: p.url || p.source || "",
          campaign: p.campaign || "",
          notes: p.notes || "",
          createdAt: p.createdAt || new Date().toISOString(),
          checkedAt: p.checkedAt || null
        }));
        saveState(false);
      }
    }
  }catch(error){
    state = defaultState();
    console.error("Local data could not be loaded",error);
    alert("اطلاعات قبلی به‌درستی خوانده نشد. قبل از پاک‌کردن داده‌های مرورگر، فایل پشتیبان را بررسی کن.");
  }
}

function saveState(showMessage=false){
  state.updatedAt = new Date().toISOString();
  try{
    localStorage.setItem(STORAGE_KEY,JSON.stringify(state));
    if(showMessage) toast("اطلاعات ذخیره شد.");
    updateAll();
    return true;
  }catch(error){
    toast("ذخیره‌سازی ناموفق بود. فضای مرورگر یا دسترسی آن را بررسی کن.");
    console.error(error);
    return false;
  }
}

function toast(message){
  $("toast").textContent = message;
  $("toast").style.display = "block";
  clearTimeout(toastTimer);
  toastTimer = setTimeout(()=>$("toast").style.display="none",3500);
}
