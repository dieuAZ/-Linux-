// CodeQL source-directory workflow from the 0922 release. Other task views
// remain on the 1013 frontend, including its non-flickering Fuzz dashboard.
const baseFillSelectsForCodeql = fillSelects;
fillSelects = function(kind) {
  if (kind !== 'codeql') return baseFillSelectsForCodeql(kind);
  const catalog = state.catalogs.codeql || {};
  const linux = $('#codeql-linux'), path = $('#codeql-driver');
  const versions = Object.keys(catalog);
  const previous = linux.value;
  linux.innerHTML = versions.length
    ? versions.map(version => `<option value="${esc(version)}">${esc(version)}</option>`).join('')
    : '<option value="">暂无可选版本</option>';
  if (versions.includes(previous)) linux.value = previous;
  enhanceVersionSelect(linux);
  const updatePaths = () => {
    path.innerHTML = '<option value="">请选择 Linux 源码相对路径</option>' +
      (catalog[linux.value] || []).map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('');
    path.value = '';
    $('#codeql-form button[type=submit]').disabled = true;
  };
  linux.onchange = () => { syncVersionPicker(linux); updatePaths(); };
  path.onchange = () => { $('#codeql-form button[type=submit]').disabled = !path.value; };
  updatePaths();
};

const baseRenderLiveCatalogForCodeql = renderLiveCatalog;
renderLiveCatalog = function(kind) {
  if (kind !== 'codeql') return baseRenderLiveCatalogForCodeql(kind);
  const box = $('#codeql-live-catalog'), catalog = state.catalogs.codeql || {};
  if (!box || box._catalogRef === catalog) return;
  box._catalogRef = catalog;
  const versions = Object.keys(catalog), selected = $('#codeql-linux')?.value || versions[0] || '';
  box.innerHTML = versions.length
    ? `<div class="catalog-browser"><div class="catalog-browser-head"><div><span class="catalog-kicker">LINUX SOURCE PATHS</span><h3>Linux 源码目录</h3></div><span class="catalog-total">${Object.values(catalog).reduce((sum, paths) => sum + paths.length, 0)} 个源码目录</span></div><label class="catalog-version-label">Linux 版本<select class="catalog-version">${versions.map(version => `<option value="${esc(version)}" ${version === selected ? 'selected' : ''}>${esc(version)}</option>`).join('')}</select></label><label class="catalog-version-label">源码相对路径<select class="codeql-source-path"></select></label><div class="catalog-search-footer">路径相对于对应 Linux 源码根目录；选择路径后同步到任务表单。</div></div>`
    : '<div class="catalog-empty">暂无可选目标</div>';
  if (!versions.length) return;
  const version = box.querySelector('.catalog-version');
  const pathSelect = box.querySelector('.codeql-source-path');
  enhanceVersionSelect(version);
  const fillPaths = () => {
    pathSelect.innerHTML = '<option value="">请选择源码路径</option>' +
      (catalog[version.value] || []).map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('');
  };
  version.onchange = () => {
    syncVersionPicker(version);
    const formVersion = $('#codeql-linux');
    formVersion.value = version.value;
    formVersion.dispatchEvent(new Event('change', {bubbles: true}));
    fillPaths();
  };
  pathSelect.onchange = () => {
    const formPath = $('#codeql-driver');
    formPath.value = pathSelect.value;
    formPath.dispatchEvent(new Event('change', {bubbles: true}));
  };
  fillPaths();
};

const baseTaskSummaryForCodeql = taskSummary;
taskSummary = function(task, report) {
  if (task.task_type !== 'CODEQL_QUERY') return baseTaskSummaryForCodeql(task, report);
  const query = report.codeql_query || {}, progress = query.progress || {}, counts = query.counts || {};
  const labels = {database:'CodeQL 数据库', irq:'IRQ 查询', hrtimer:'hrtimer 查询',
    kthread:'kthread 查询', napi:'NAPI 查询', rcu:'RCU 查询', tasklet:'tasklet 查询',
    timer:'timer 查询', workqueue:'workqueue 查询', ops:'ops 查询',
    merge:'结果融合', llm_review:'大模型复核'};
  const errorLine = counts.review_errors == null ? '' :
    `<div class="config-line"><span>大模型错误</span><b>${counts.review_errors} 条</b></div>`;
  const retrying = codeqlRetryPending.has(task.id);
  const actions = ['COMPLETED', 'COMPLETED_WITH_WARNINGS'].includes(task.status)
    ? `<div class="codeql-actions"><a class="primary codeql-download" href="/api/tasks/${task.id}/codeql-result">下载最终复核 CSV</a><button type="button" class="codeql-retry" style="margin-left:8px" ${retrying ? 'disabled' : ''} onclick="retryCodeqlErrors('${task.id}', this)">${retrying ? '重试中…' : '重试错误'}</button></div>` : '';
  return Object.keys(labels).map(key => `<div class="config-line"><span>${labels[key]}</span><b>${esc(progress[key] || '等待上报')}${counts[key] == null ? '' : ` · ${counts[key]} 条`}</b></div>`).join('') + errorLine + actions;
};

const codeqlRetryPending = new Set();
window.retryCodeqlErrors = async function(taskId, button) {
  codeqlRetryPending.add(taskId);
  button.disabled = true;
  button.textContent = '重试中…';
  try {
    const response = await fetch(`/api/tasks/${taskId}/codeql-retry-errors`, {method: 'POST'});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || '请求失败');
    // The task detail view auto-refreshes every 2s; no page reload (that would
    // drop the in-memory route and bounce back to the task list).
    setTimeout(() => {
      codeqlRetryPending.delete(taskId);
      if (typeof refreshTask === 'function') refreshTask(taskId);
    }, 120000);
  } catch (error) {
    codeqlRetryPending.delete(taskId);
    alert('重试失败：' + error.message);
    button.disabled = false;
    button.textContent = '重试错误';
  }
};
