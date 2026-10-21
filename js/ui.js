"use strict";

function showPage(name){
  document.querySelectorAll(".page").forEach(p=>p.classList.remove("active"));
  document.querySelectorAll(".navbtn").forEach(b=>b.classList.toggle("active",b.dataset.page===name));
  const target = $("page-"+name);
  if(target) target.classList.add("active");
  updateAll();
}

document.querySelectorAll(".navbtn").forEach(button=>{
  button.addEventListener("click",()=>showPage(button.dataset.page));
});

function openModal(id){$(id).classList.add("open")}
function closeModal(id){$(id).classList.remove("open")}

document.querySelectorAll(".modal").forEach(modal=>{
  modal.addEventListener("click",e=>{
    if(e.target===modal) modal.classList.remove("open");
  });
});

function openBackup(){openModal("backupModal")}
