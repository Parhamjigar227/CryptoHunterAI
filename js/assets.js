"use strict";

/* ASSETS */

function openAssetForm(id=null){
  $("assetForm").reset();
  $("assetId").value = "";
  $("assetFormTitle").textContent = "افزودن دارایی";
  $("aQuantity").value = "0";
  $("aPrice").value = "0";

  if(id){
    const a = state.assets.find(x=>x.id===id);
    if(!a) return;
    $("assetId").value = a.id;
    $("assetFormTitle").textContent = "ویرایش دارایی";
    $("aName").value = a.name || "";
    $("aSymbol").value = a.symbol || "";
    $("aQuantity").value = num(a.quantity);
    $("aPrice").value = num(a.price);
    $("aNotes").value = a.notes || "";
  }
  openModal("assetModal");
}

$("assetForm").addEventListener("submit",e=>{
  e.preventDefault();
  const id = $("assetId").value;
  const symbol = $("aSymbol").value.trim().toUpperCase();
  const name = $("aName").value.trim();
  if(!name || !symbol){toast("نام و نماد دارایی لازم است.");return}

  const duplicate = state.assets.find(a=>a.id!==id && a.symbol.toUpperCase()===symbol);
  if(duplicate && !confirm("این نماد قبلاً ثبت شده است. دارایی تکراری بسازیم؟")) return;

  const asset = {
    id:id || uid(),
    name,
    symbol,
    quantity:Math.max(0,num($("aQuantity").value)),
    price:Math.max(0,num($("aPrice").value)),
    notes:$("aNotes").value.trim(),
    updatedAt:new Date().toISOString()
  };

  const existing = state.assets.find(a=>a.id===id);
  if(existing) Object.assign(existing,asset);
  else state.assets.push(asset);

  closeModal("assetModal");
  saveState();
  toast("دارایی ذخیره شد.");
});

function getAssetStats(asset){
  const txs = state.transactions
    .filter(t=>t.assetId===asset.id)
    .slice()
    .sort((a,b)=>String(a.date).localeCompare(String(b.date)));

  let qty=0, cost=0, realized=0;

  for(const t of txs){
    const q=num(t.quantity), price=num(t.price), fee=num(t.fee);
    if(t.type==="buy"){
      qty+=q;
      cost+=q*price+fee;
    }else if(t.type==="reward"){
      qty+=q;
      // Rewards are recorded with zero cost basis in this simple model.
    }else if(t.type==="sell"){
      if(qty>0 && q<=qty){
        const avg=cost/qty;
        realized+=(q*price-fee)-(avg*q);
        cost-=avg*q;
        qty-=q;
        if(qty<1e-10){qty=0;cost=0}
      }
    }else if(t.type==="fee"){
      qty=Math.max(0,qty-q);
      if(qty===0) cost=0;
      else cost=Math.max(0,cost-(cost/(qty+q))*q);
    }
  }

  const hasTx = txs.length>0;
  const quantity = hasTx ? qty : num(asset.quantity);
  const basis = hasTx ? cost : 0;
  const value = quantity*num(asset.price);
  const unrealized = hasTx ? value-basis : null;

  return {quantity,cost:basis,value,realized,unrealized,hasTx};
}

function renderAssets(){
  if(!state.assets.length){
    $("assetTable").innerHTML='<tr><td colspan="7" class="empty">هنوز دارایی ثبت نشده است.</td></tr>';
    return;
  }

  $("assetTable").innerHTML = state.assets.map(a=>{
    const s=getAssetStats(a);
    const avg=s.quantity>0 && s.hasTx ? s.cost/s.quantity : 0;
    const plText=s.unrealized===null ? "نامشخص" : fmt(s.unrealized);
    const plClass=s.unrealized===null ? "" : (s.unrealized>=0?"positive":"negative");
    return `<tr>
      <td><strong>${escapeHTML(a.name)}</strong><br><span class="muted">${escapeHTML(a.symbol)}</span></td>
      <td>${fmt(s.quantity,8)}</td>
      <td>${s.hasTx?fmt(avg):"نامشخص"}</td>
      <td>${fmt(a.price)}</td>
      <td>${fmt(s.value)}</td>
      <td class="${plClass}">${plText}</td>
      <td><div class="actions">
        <button class="btn small" onclick="openAssetForm('${a.id}')">ویرایش</button>
        <button class="btn small danger" onclick="deleteAsset('${a.id}')">حذف</button>
      </div></td>
    </tr>`;
  }).join("");
}

function deleteAsset(id){
  const a=state.assets.find(x=>x.id===id);
  if(!a) return;
  const hasTx=state.transactions.some(t=>t.assetId===id);
  const msg=hasTx
    ?"برای این دارایی تراکنش ثبت شده است. حذف آن محاسبات را تغییر می‌دهد. ادامه؟"
    :"این دارایی حذف شود؟";
  if(!confirm(msg)) return;
  state.assets=state.assets.filter(x=>x.id!==id);
  state.transactions=state.transactions.filter(x=>x.assetId!==id);
  saveState();
  toast("دارایی و تراکنش‌های مرتبط حذف شدند.");
}
