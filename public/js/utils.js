"use strict";

/*
 CryptoHunterAI - Local Prototype
 This file does not fetch live prices or discover projects online.
 All values and transaction data are user-entered.
*/

const STORAGE_KEY = "CryptoHunterAI_v2";
const $ = id => document.getElementById(id);

const defaultState = () => ({
  version: 2,
  createdAt: new Date().toISOString(),
  updatedAt: null,
  projects: [],
  assets: [],
  transactions: [],
  reports: []
});

let state = defaultState();
let toastTimer = null;

function uid(){
  return Date.now().toString(36) + Math.random().toString(36).slice(2,8);
}

function num(value){
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function fmt(value, digits=2){
  return num(value).toLocaleString("en-US",{
    minimumFractionDigits:0,
    maximumFractionDigits:digits
  });
}

function faDate(value){
  if(!value) return "—";
  const d = new Date(value.length === 10 ? value+"T12:00:00" : value);
  if(Number.isNaN(d.getTime())) return value;
  return d.toLocaleDateString("fa-IR");
}

function dateToday(){
  const d = new Date();
  return d.getFullYear()+"-"+String(d.getMonth()+1).padStart(2,"0")+"-"+String(d.getDate()).padStart(2,"0");
}

function escapeHTML(value){
  return String(value ?? "").replace(/[&<>"']/g, c => ({
    "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
  }[c]));
}

function safeUrl(value){
  if(!value) return "";
  try{
    const u = new URL(value);
    if(u.protocol === "https:" || u.protocol === "http:") return u.href;
  }catch(e){}
  return "";
}
