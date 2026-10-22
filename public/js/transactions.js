"use strict";

/* TRANSACTIONS */

function refreshTransactionAssetOptions(){
  const select=$("tAsset");
  const previous=select.value;
  select.innerHTML='<option value="">انتخاب دارایی</option>'+
    state.assets.map(a=>`<option value="${a.id}">${escapeHTML(a.name)} (${escapeHTML(a.symbol)})</option>`).join("");
  if(state.assets.some(a=>a.id===previous)) select.value=previous;
}

function openTransactionForm(){
  if(!state.assets.length){
    toast("ابتدا از بخش سبد دارایی، یک دارایی ثبت کن.");
    showPage("portfolio");
    return;
  }
  $("transactionForm").reset();
  refreshTransactionAssetOptions();
  $("tDate").value=dateToday();
  $("tPrice").value="0";
  $("tFee").value="0";
  openModal("transactionModal");
}

$("transactionForm").addEventListener("submit",e=>{
  e.preventDefault();
  const asset=state.assets.find(a=>a.id===$("tAsset").value);
  if(!asset){toast("دارایی را انتخاب کن.");return}

  const type=$("tType").value;
  const quantity=num($("tQuantity").value);
  const price=Math.max(0,num($("tPrice").value));
  const fee=Math.max(0,num($("tFee").value));
  if(quantity<=0){toast("مقدار باید بیشتر از صفر باشد.");return}

  const stats=getAssetStats(asset);
  if((type==="sell" || type==="fee") && quantity>stats.quantity+1e-10){
    toast("موجودی کافی نیست. مقدار فعلی: "+fmt(stats.quantity,8));
    return;
  }

  state.transactions.push({
    id:uid(),
    assetId:asset.id,
    type,
    quantity,
    price,
    fee,
    date:$("tDate").value || dateToday(),
    notes:$("tNotes").value.trim(),
    createdAt:new Date().toISOString()
  });

  closeModal("transactionModal");
  saveState();
  toast("تراکنش ثبت شد.");
});

const txLabels={buy:"خرید",sell:"فروش",reward:"پاداش دریافتی",fee:"کارمزد به واحد ارز"};

function renderTransactions(){
  const txs=state.transactions.slice().sort((a,b)=>String(b.date).localeCompare(String(a.date)));
  if(!txs.length){
    $("transactionTable").innerHTML='<tr><td colspan="7" class="empty">تراکنشی ثبت نشده است.</td></tr>';
    return;
  }

  $("transactionTable").innerHTML=txs.map(t=>{
    const a=state.assets.find(x=>x.id===t.assetId);
    return `<tr>
      <td>${faDate(t.date)}</td>
      <td>${escapeHTML(a?a.symbol:"دارایی حذف‌شده")}</td>
      <td>${escapeHTML(txLabels[t.type]||t.type)}</td>
      <td>${fmt(t.quantity,8)}</td>
      <td>${fmt(t.price)}</td>
      <td>${fmt(t.fee)}</td>
      <td><button class="btn small danger" onclick="deleteTransaction('${t.id}')">حذف</button></td>
    </tr>`;
  }).join("");
}

function deleteTransaction(id){
  if(!confirm("این تراکنش حذف شود؟ محاسبات سبد دوباره انجام می‌شود.")) return;
  state.transactions=state.transactions.filter(t=>t.id!==id);
  saveState();
  toast("تراکنش حذف شد.");
}
