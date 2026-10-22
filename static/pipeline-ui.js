// The configuration view and running view are intentionally separate.
const launchPageOriginal = loadLaunchPage;
let pipelineSelection = null;
let pipelineItems = [];
let pipelineRequest = false;
const launchSection = document.querySelector('#view-launch');
const launchModes = document.createElement('div');
launchModes.className = 'pipeline-modebar';
launchModes.innerHTML = '<button class="quiet" id="pipeline-config-mode">启动配置</button><button class="quiet hidden" id="pipeline-running-mode">运行流水线</button>';
launchSection.querySelector('.heading').after(launchModes);
const pipelinePanel = document.createElement('article');
pipelinePanel.className = 'panel pipeline-runtime hidden';
pipelinePanel.innerHTML = '<div class="panel-title"><h2>运行流水线</h2><button class="quiet" id="pipeline-new">新建启动</button></div><div id="pipeline-tabs" class="live-log-tabs"></div><div id="pipeline-summary"></div><div id="pipeline-task-links"></div><pre id="pipeline-log" class="logbox live-logbox"></pre>';
launchSection.append(pipelinePanel);
const pipelineStyle = document.createElement('style');
pipelineStyle.textContent = '.pipeline-modebar{display:flex;gap:10px;margin-bottom:20px}.pipeline-runtime{overflow:hidden}.pipeline-runtime .logbox{height:380px;min-height:380px;max-height:380px;overflow:auto;margin:0}.pipeline-facts{display:flex;flex-wrap:wrap;gap:24px;padding:24px}.pipeline-facts b{display:block;margin-top:8px}.pipeline-task-links{display:flex;flex-wrap:wrap;gap:8px;padding:0 24px 20px}.pipeline-error{color:#b42318;padding:0 24px 20px}.pipeline-runtime .live-log-tabs{overflow-x:auto}.pipeline-modebar button.active{background:#eaf0ff;color:#3d63df}.pipeline-runtime .live-log-tabs button.active{border-color:#3d63df;background:#edf2ff}';
document.head.append(pipelineStyle);

function pipelineMode(running) {
  launchSection.querySelector('.launch-layout').classList.toggle('hidden', running);
  pipelinePanel.classList.toggle('hidden', !running);
  document.querySelector('#pipeline-config-mode').classList.toggle('active', !running);
  document.querySelector('#pipeline-running-mode').classList.toggle('active', running);
}
document.querySelector('#pipeline-config-mode').onclick = () => pipelineMode(false);
document.querySelector('#pipeline-new').onclick = () => { pipelineMode(false); clearLaunchTarget(); searchLaunchTargets(); };
document.querySelector('#pipeline-running-mode').onclick = () => pipelineMode(true);

loadLaunchPage = async function() {
  await launchPageOriginal();
  await loadPipelines(true);
  if (state.launchTimer) clearInterval(state.launchTimer);
  state.launchTimer = setInterval(() => loadPipelines(false), 2000);
};

async function loadPipelines(initial=false) {
  if (pipelineRequest) return;
  pipelineRequest = true;
  try {
    pipelineItems = (await api('/api/pipelines')).items;
    document.querySelector('#pipeline-running-mode').classList.toggle('hidden', !pipelineItems.length);
    if (!pipelineItems.length) { pipelineMode(false); return; }
    if (!pipelineItems.some(p => p.id === pipelineSelection)) pipelineSelection = (pipelineItems.find(p => ['RUNNING','QUEUED','STOPPING','INTERRUPTED'].includes(p.status)) || pipelineItems[0]).id;
    if (initial) pipelineMode(pipelineItems.some(p => ['RUNNING','QUEUED','STOPPING','INTERRUPTED'].includes(p.status)));
    document.querySelector('#pipeline-tabs').innerHTML = pipelineItems.map(p => `<button type="button" data-pipeline-id="${p.id}" class="${p.id === pipelineSelection ? 'active' : ''}">${esc(p.driver)} · ${esc(p.linux_version)} <small>${esc(p.status)}</small></button>`).join('');
    document.querySelectorAll('[data-pipeline-id]').forEach(b => b.onclick = () => { pipelineSelection = b.dataset.pipelineId; loadPipelines(); });
    const p = pipelineItems.find(p => p.id === pipelineSelection);
    const titles = {STATIC_ANALYSIS:'静态分析',PROBE:'驱动 Probe',FUZZ:'Fuzz',SEED:'种子生成',QUEUED:'等待资源',FINISHED:'已结束'};
    document.querySelector('#pipeline-summary').innerHTML = `<div class="pipeline-facts"><div>当前阶段<b>${titles[p.stage] || esc(p.stage)}</b></div><div>状态<b>${esc(p.status)}</b></div><div>轮次<b>${p.round}</b></div><div>本轮时间<b>${p.elapsed_seconds || 0} 秒 / ${p.max_duration_minutes} 分钟</b></div><div>收敛窗口<b>${p.convergence_elapsed_seconds || 0} 秒 / ${p.convergence_window_minutes} 分钟</b></div><div>覆盖点<b>${p.coverage_pcs ?? '等待上报'}</b></div>${['QUEUED','RUNNING'].includes(p.status)?'<button class="quiet" id="pipeline-stop">停止流水线</button>':''}${p.status==='INTERRUPTED'?'<button class="quiet" id="pipeline-release">确认旧进程已清理</button>':''}</div>${p.error?`<div class="pipeline-error">${esc(p.error)}</div>`:''}`;
    const links = document.querySelector('#pipeline-task-links');
    links.className='pipeline-task-links';
    links.innerHTML = Object.entries(p.reused).map(([kind,id])=>`<button class="quiet" data-pipeline-task="${id}">${titles[kind]} · 已复用</button>`).join('') + p.tasks.map((id,i)=>`<button class="quiet" data-pipeline-task="${id}">阶段任务 ${i+1}${id===p.current_task_id?' · 当前':''}</button>`).join('');
    links.querySelectorAll('button').forEach(b=>b.onclick=()=>openTask(b.dataset.pipelineTask));
    const stop=document.querySelector('#pipeline-stop');
    if(stop) stop.onclick=async()=>{if(!confirm('停止此流水线及其正在执行的任务？'))return;try{await api(`/api/pipelines/${p.id}/stop`,{method:'POST',body:'{}'});loadPipelines()}catch(e){notice(e.message)}};
    const release=document.querySelector('#pipeline-release');
    if(release) release.onclick=async()=>{if(!confirm('请先在服务器确认此流水线的 QEMU、Docker 和分析进程全部停止。确认解除占用？'))return;try{await api(`/api/pipelines/${p.id}/release`,{method:'POST',body:JSON.stringify({confirmed:true})});loadPipelines()}catch(e){notice(e.message)}};
    const log=document.querySelector('#pipeline-log');
    const atBottom=log.scrollHeight-log.scrollTop-log.clientHeight<40;
    const selected=p.id;
    const output=p.current_task_id?await api(`/api/tasks/${p.current_task_id}/logs/${p.stage==='SEED'?'seed':'workflow'}`):{content:'等待调度…'};
    if(selected===pipelineSelection){log.textContent=output.content||'等待日志…';if(atBottom)log.scrollTop=log.scrollHeight;}
  } catch(e) { notice(`无法读取流水线：${e.message}`); }
  finally { pipelineRequest=false; }
}

reviewLaunch = async function(event) {
  event.preventDefault();
  const form=event.currentTarget, button=form.querySelector('[type="submit"]');
  if(button.disabled)return;
  if(!state.launchTarget){notice('请先选择驱动');return;}
  const values=new FormData(form);
  const payload={linux_version:values.get('linux_version'),driver:state.launchTarget.driver,
    extra_enabled:values.has('extra_enabled'),reuse_results:values.has('reuse_results'),auto_seed:values.has('auto_seed'),
    convergence_window_minutes:Number(values.get('convergence_window_minutes')),max_duration_minutes:Number(values.get('max_duration_minutes'))};
  button.disabled=true;button.textContent='正在提交…';notice('');
  try {
    const item=await api('/api/pipelines',{method:'POST',body:JSON.stringify(payload)});
    pipelineSelection=item.id;
    await loadPipelines();pipelineMode(true);clearLaunchTarget();
  } catch(e) {notice(e.message);}
  finally {button.disabled=false;button.textContent='检查并启动';}
};
document.querySelector('#launch-form').onsubmit=reviewLaunch;
const codeqlTaskSummary=window.taskSummary;
window.taskSummary=function(task,report){const rendered=codeqlTaskSummary(task,report);if(task.task_type!=='CODEQL_QUERY')return rendered;const counts=report.codeql_query?.counts||{},seconds=Math.max(0,Number(counts.runtime_seconds)||0),duration=`${Math.floor(seconds/3600).toString().padStart(2,'0')}:${Math.floor(seconds%3600/60).toString().padStart(2,'0')}:${Math.floor(seconds%60).toString().padStart(2,'0')}`,number=value=>Number(value||0).toLocaleString();const stats=`<div class="config-line"><span>总耗时</span><b>${duration}</b></div><div class="config-line"><span>Token 用量</span><b>${number(counts.total_tokens)}</b></div><div class="config-line"><span>安全 / 需复核 / 危险 / 错误</span><b>${number(counts.safe)} / ${number(counts.manual)} / ${number(counts.dangerous)} / ${number(counts.review_errors ?? counts.errors)}</b></div>`;return rendered.includes('<a class="primary codeql-download"')?rendered.replace('<a class="primary codeql-download"',`${stats}<a class="primary codeql-download"`):rendered+stats};
const appFetch=window.fetch.bind(window);
window.fetch=(input,options={})=>{const url=typeof input==='string'?input:input.url,form=document.getElementById('codeql-form'),retry=form?.querySelector('[name="auto_retry_errors"]');if(url?.endsWith('/api/tasks')&&options.method==='POST'&&retry){try{const payload=JSON.parse(options.body||'{}');if(payload.task_type==='CODEQL_QUERY'){payload.auto_retry_errors=retry.checked;options={...options,body:JSON.stringify(payload)}}}catch{}}return appFetch(input,options)};
document.addEventListener('DOMContentLoaded',()=>{const form=document.getElementById('codeql-form'),reuse=form?.querySelector('[name="reuse_database"]');if(!form||!reuse)return;const label=document.createElement('label');label.className='toggle';label.innerHTML='<input name="auto_retry_errors" type="checkbox"><i></i><span><strong>自动重试模型错误项（最多 3 次）</strong></span>';reuse.closest('label').after(label)});
