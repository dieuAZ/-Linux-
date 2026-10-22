// A shared real-data dashboard for individual Fuzz tasks and one-click pipelines.
const fuzzDashWindows = {detail: 120, pipeline: 120};
const fuzzDashRequests = new Map();
function fuzzNumber(value) {
  return Number.isFinite(value) ? Math.trunc(value).toLocaleString('zh-CN') : '等待数据';
}
function fuzzDuration(seconds) {
  if (!Number.isFinite(seconds)) return '等待启动';
  const total = Math.max(0, Math.floor(seconds));
  return `${String(Math.floor(total / 3600)).padStart(2,'0')}:${String(Math.floor(total % 3600 / 60)).padStart(2,'0')}:${String(total % 60).padStart(2,'0')}`;
}
function fuzzChart(samples, minutes) {
  const end = Date.parse(samples.at(-1)?.at || '');
  const visible = samples.filter(point => Number.isFinite(Date.parse(point.at)) && Date.parse(point.at) >= end - minutes * 60000 && Number.isFinite(point.coverage_pcs));
  if (visible.length < 2) return '<div class="fuzz-chart-empty">收到至少两次覆盖点记录后，这里会显示真实趋势</div>';
  const width=700,height=230,left=60,right=18,top=17,bottom=38;
  const values=visible.map(point=>point.coverage_pcs);
  const high=Math.max(...values),low=Math.min(...values),padding=Math.max(1,(high-low)*.14);
  const yMin=Math.max(0,Math.floor(low-padding)),yMax=Math.ceil(high+padding);
  const start=Date.parse(visible[0].at),finish=Date.parse(visible.at(-1).at);
  const x=point=>left+(Date.parse(point.at)-start)/Math.max(1,finish-start)*(width-left-right);
  const y=value=>top+(yMax-value)/Math.max(1,yMax-yMin)*(height-top-bottom);
  const line=visible.map((point,index)=>`${index?'L':'M'}${x(point).toFixed(1)},${y(point.coverage_pcs).toFixed(1)}`).join(' ');
  const area=`${line} L${x(visible.at(-1)).toFixed(1)},${height-bottom} L${x(visible[0]).toFixed(1)},${height-bottom} Z`;
  const ticks=[0, .5, 1].map(frac=>{const py=y(yMin+(yMax-yMin)*frac);return `<line x1="${left}" y1="${py}" x2="${width-right}" y2="${py}" stroke="#e9edf5" stroke-dasharray="4 5"/><text x="${left-10}" y="${py+4}" text-anchor="end" fill="#9aa6ba" font-size="11">${fuzzNumber(yMin+(yMax-yMin)*frac)}</text>`}).join('');
  const timeLabel=at=>new Date(at).toLocaleTimeString('zh-CN',{hour:'2-digit',minute:'2-digit'});
  return `<svg class="fuzz-chart-svg" viewBox="0 0 ${width} ${height}" role="img" aria-label="实际覆盖点趋势"><defs><linearGradient id="fuzz-coverage-fill" x1="0" x2="0" y1="0" y2="1"><stop offset="0%" stop-color="#4773e5" stop-opacity=".20"/><stop offset="100%" stop-color="#4773e5" stop-opacity="0"/></linearGradient></defs>${ticks}<path d="${area}" fill="url(#fuzz-coverage-fill)"/><path d="${line}" fill="none" stroke="#426fe0" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/><circle cx="${x(visible.at(-1))}" cy="${y(visible.at(-1).coverage_pcs)}" r="5" fill="#426fe0" stroke="white" stroke-width="3"/><text x="${left}" y="${height-9}" fill="#9aa6ba" font-size="11">${timeLabel(start)}</text><text x="${width-right}" y="${height-9}" text-anchor="end" fill="#9aa6ba" font-size="11">${timeLabel(finish)}</text></svg>`;
}
function fuzzDashboardHtml(data,scope) {
  const last=data.last||{},samples=Array.isArray(data.samples)?data.samples:[];
  const minutes=fuzzDashWindows[scope];
  const stop=data.task_status==='RUNNING'||data.task_status==='READY_FOR_FUZZ'?Date.now():Date.parse(data.finished_at||last.at||'');
  const duration=data.pipeline?.elapsed_seconds ?? (Number.isFinite(stop)&&Number.isFinite(Date.parse(data.started_at))?Math.max(0,(stop-Date.parse(data.started_at))/1000):null);
  const sampleTime=last.at?new Date(last.at).toLocaleString('zh-CN'):'等待首条状态记录';
  const configured=Number.isInteger(data.configured_vms)?`${data.configured_vms} 台已配置`:'未提供';
  const crashLabel=data.crash_source==='workdir'?'根据 Crash 目录统计':'根据已读取日志中的不同 Crash 标题统计';
  const live=['RUNNING','READY_FOR_FUZZ','STARTING'].includes(data.task_status);
  const fresh=Number.isFinite(Date.parse(last.at))&&Math.abs(Date.now()-Date.parse(last.at))<60000;
  return `<div class="fuzz-dash-cards"><article><span>执行程序</span><strong>${fuzzNumber(last.executions)}</strong><small>Syzkaller 已执行总数</small></article><article><span>Corpus</span><strong>${fuzzNumber(last.corpus_count)}</strong><small>当前语料数量</small></article><article><span>代码覆盖</span><strong>${fuzzNumber(last.coverage_pcs)}</strong><small>覆盖点（PCs）</small></article><article class="fuzz-dash-crash"><span>发现 Crash</span><strong>${fuzzNumber(data.crash_count)}</strong><small>${crashLabel}</small></article></div><div class="fuzz-dash-main"><article class="fuzz-dash-chart"><div class="fuzz-dash-title"><div><h2>覆盖点趋势</h2><small>使用 Syzkaller 实际状态记录 · 最近 ${minutes} 分钟</small></div><div class="fuzz-dash-period"><button type="button" data-fuzz-window="30" class="${minutes===30?'active':''}">30 分钟</button><button type="button" data-fuzz-window="120" class="${minutes===120?'active':''}">2 小时</button></div></div>${fuzzChart(samples,minutes)}</article><article class="fuzz-dash-runtime"><div class="fuzz-dash-title"><h2>运行状态</h2><span class="fuzz-dash-live">${live?(fresh?'实时更新':'日志待更新'):'历史记录'}</span></div><div class="fuzz-dash-runtime-grid"><div><span>${data.pipeline?.stage==='FUZZ'?'本轮已运行':'任务已运行'}</span><strong>${fuzzDuration(duration)}</strong></div><div><span>虚拟机配置</span><strong>${configured}</strong></div></div><div class="fuzz-dash-line"><span>当前轮次</span><b>${data.pipeline?.round?`第 ${data.pipeline.round} 轮`:'—'}</b></div><div class="fuzz-dash-line"><span>执行速度</span><b>${Number.isFinite(last.execs_per_sec)?`${fuzzNumber(last.execs_per_sec)} 次/秒`:'等待数据'}</b></div><div class="fuzz-dash-line"><span>最新采样</span><b>${esc(sampleTime)}</b></div><p class="fuzz-dash-note">虚拟机 CPU 占用未接入，页面不显示估算值。</p></article></div>`;
}
async function refreshFuzzDashboard(id,scope) {
  const box=document.querySelector(`#fuzz-dashboard-${scope}`);
  if(!box || fuzzDashRequests.get(scope)) return;
  fuzzDashRequests.set(scope,true);
  try {
    const data=await api(`/api/tasks/${id}/telemetry`);
    if(!box.isConnected || box.dataset.taskId!==id) return;
    renderFuzzDashboard(box,data,scope,id);
  } catch(error) {
    if(box.isConnected && box.dataset.taskId===id){
      const badge=box.querySelector('.fuzz-dash-live');
      if(badge){badge.textContent='统计暂不可用';box.dataset.renderedHtml=''}
      else{const html=`<div class="fuzz-dash-error">实时统计读取失败：${esc(error.message)}</div>`;if(box.dataset.renderedHtml!==html){box.innerHTML=html;box.dataset.renderedHtml=html}}
    }
  } finally {fuzzDashRequests.delete(scope)}
}
function renderFuzzDashboard(box,data,scope,id){
  const html=fuzzDashboardHtml(data,scope);
  if(box.dataset.renderedHtml===html)return;
  if(box.dataset.renderedTaskId!==id || !box.querySelector('.fuzz-dash-cards')){
    box.innerHTML=html;
  }else{
    const next=document.createElement('div');next.innerHTML=html;
    const selectors=['.fuzz-dash-cards strong','.fuzz-dash-cards small','.fuzz-dash-runtime-grid span','.fuzz-dash-runtime-grid strong','.fuzz-dash-line b','.fuzz-dash-live','.fuzz-dash-period button'];
    for(const selector of selectors){
      const current=box.querySelectorAll(selector),incoming=next.querySelectorAll(selector);
      if(current.length!==incoming.length){box.innerHTML=html;break}
      current.forEach((node,index)=>{if(node.textContent!==incoming[index].textContent)node.textContent=incoming[index].textContent;if(node.className!==incoming[index].className)node.className=incoming[index].className});
    }
    const chart=box.querySelector('.fuzz-chart-svg, .fuzz-chart-empty'),newChart=next.querySelector('.fuzz-chart-svg, .fuzz-chart-empty');
    if(chart && newChart && chart.outerHTML!==newChart.outerHTML)chart.replaceWith(newChart);
  }
  box.dataset.renderedHtml=html;box.dataset.renderedTaskId=id;
  box.querySelectorAll('[data-fuzz-window]').forEach(button=>button.onclick=()=>{
    fuzzDashWindows[scope]=Number(button.dataset.fuzzWindow);
    renderFuzzDashboard(box,data,scope,id);
    refreshFuzzDashboard(id,scope);
  });
}
const baseRenderFuzzDetail=renderDetail;
renderDetail=function(task,logs,events){
  const previous=document.querySelector('#fuzz-dashboard-detail');
  const box=previous?.dataset.taskId===task.id?previous:null;
  baseRenderFuzzDetail(task,logs,events);
  if(task.task_type!=='FUZZ')return;
  if(!box){const fresh=document.createElement('section');fresh.className='fuzz-dashboard';fresh.id='fuzz-dashboard-detail';fresh.dataset.taskId=task.id;fresh.innerHTML='<div class="fuzz-dash-loading">正在读取实时统计…</div>';document.querySelector('#task-detail .facts').after(fresh)}
  else if(!box.isConnected)document.querySelector('#task-detail .facts').after(box);
  refreshFuzzDashboard(task.id,'detail');
};
const baseLoadFuzzPipelines=loadPipelines;
loadPipelines=async function(initial=false){
  await baseLoadFuzzPipelines(initial);
  const selected=pipelineItems.find(item=>item.id===pipelineSelection);
  const runtime=document.querySelector('.pipeline-runtime');
  let box=document.querySelector('#fuzz-dashboard-pipeline');
  if(selected?.stage!=='FUZZ' || !selected.current_task_id || runtime.classList.contains('hidden')){
    if(box)box.remove();
    return;
  }
  if(!box){box=document.createElement('section');box.className='fuzz-dashboard';box.id='fuzz-dashboard-pipeline';
    document.querySelector('#pipeline-summary').after(box)}
  if(box.dataset.taskId!==selected.current_task_id){box.dataset.renderedHtml='';box.dataset.renderedTaskId=''}
  box.dataset.taskId=selected.current_task_id;
  refreshFuzzDashboard(selected.current_task_id,'pipeline');
};
