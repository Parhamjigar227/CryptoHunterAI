"use strict";

/* BACKUP */

function downloadBlob(content,filename,type){
  const blob=new Blob([content],{type});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url;a.download=filename;
  document.body.appendChild(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),1500);
}

function exportBackup(){
  const payload={
    app:"CryptoHunterAI",
    backupVersion:1,
    exportedAt:new Date().toISOString(),
    data:state
  };
  downloadBlob(JSON.stringify(payload,null,2),"CryptoHunterAI_Backup_"+dateToday()+".json","application/json");
  toast("فایل پشتیبان آماده شد.");
}

function importBackup(){
  const file=$("importFile").files[0];
  if(!file){toast("ابتدا فایل JSON را انتخاب کن.");return}
  if(!confirm("بازیابی، اطلاعات فعلی را با اطلاعات فایل جایگزین می‌کند. ابتدا پشتیبان فعلی را دانلود کرده‌ای؟")) return;

  const reader=new FileReader();
  reader.onload=()=>{
    try{
      const parsed=JSON.parse(reader.result);
      const incoming=parsed.data || parsed;
      if(!incoming || !Array.isArray(incoming.projects) ||
         !Array.isArray(incoming.assets) || !Array.isArray(incoming.transactions)){
        throw new Error("Invalid backup structure");
      }
      if(!confirm("تعداد پروژه‌ها: "+incoming.projects.length+
        "\nتعداد دارایی‌ها: "+incoming.assets.length+
        "\nتعداد تراکنش‌ها: "+incoming.transactions.length+
        "\n\nاین اطلاعات جایگزین داده‌های فعلی شوند؟")) return;

      state={
        ...defaultState(),
        ...incoming,
        projects:incoming.projects,
        assets:incoming.assets,
        transactions:incoming.transactions,
        reports:Array.isArray(incoming.reports)?incoming.reports:[]
      };

      if(saveState()){
        $("importFile").value="";
        toast("بازیابی انجام شد.");
      }
    }catch(error){
      alert("فایل پشتیبان معتبر نیست یا قابل خواندن نیست.");
      console.error(error);
    }
  };
  reader.onerror=()=>toast("خواندن فایل ناموفق بود.");
  reader.readAsText(file);
}

function checkStorage(){
  try{
    const bytes=new Blob([localStorage.getItem(STORAGE_KEY)||""]).size;
    $("storageInfo").textContent=
      "اطلاعات برنامه در این مرورگر ذخیره شده است. حجم تقریبی: "+
      fmt(bytes/1024,1)+" کیلوبایت. این عدد ظرفیت باقی‌ماندهٔ مرورگر نیست.";
  }catch(error){
    $("storageInfo").textContent="بررسی ذخیره‌سازی ناموفق بود.";
  }
}

function clearAll(){
  if(!confirm("تمام پروژه‌ها، دارایی‌ها، تراکنش‌ها و گزارش‌ها پاک شوند؟")) return;
  if(!confirm("این کار قابل برگشت نیست مگر اینکه فایل پشتیبان داشته باشی. مطمئنی؟")) return;
  state=defaultState();
  saveState();
  toast("اطلاعات محلی برنامه پاک شد.");
}
