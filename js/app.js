"use strict";

function updateAll(){
  renderProjects();
  renderAssets();
  renderTransactions();
  updateDashboard();
  renderReport();
  refreshTransactionAssetOptions();
}

loadState();
updateAll();
