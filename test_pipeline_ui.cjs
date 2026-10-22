// Verify submission wiring without launching real backend tasks or a browser.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
function element() {
  return {className:'',innerHTML:'',textContent:'',disabled:false,
    classList:{toggle(){},add(){},remove(){}},after(){},append(){},querySelector(){return element()},querySelectorAll(){return []}};
}
const nodes = new Map();
const get = s => {if(!nodes.has(s))nodes.set(s,element());return nodes.get(s)};
const requests=[];
let error=null;
const context = vm.createContext({
  document:{querySelector:get,querySelectorAll:()=>[],createElement:element,head:element(),addEventListener(){}},
  window:{taskSummary(){return ''},fetch(){}},
  state:{launchTarget:{driver:'vmxnet3'}},loadLaunchPage:async()=>{},
  api:async(path,options)=>{requests.push({path,options});return {id:'pipeline-1'}},
  notice:message=>{error=message},esc:String,openTask(){},clearLaunchTarget(){},searchLaunchTargets(){},
  clearInterval(){},setInterval(){},confirm:()=>true,
  FormData:class {constructor(form){this.values=form.values}get(k){return this.values[k]}has(k){return !!this.values[k]}}
});
vm.runInContext(fs.readFileSync('static/pipeline-ui.js','utf8'),context);
vm.runInContext('loadPipelines=async()=>{}; pipelineMode=()=>{};',context);
async function main(){
  const button=element();
  const event={preventDefault(){},currentTarget:{querySelector:()=>button,values:{linux_version:'linux-7.1.5',reuse_results:true,auto_seed:true,convergence_window_minutes:'30',max_duration_minutes:'180'}}};
  await get('#launch-form').onsubmit(event);
  assert.equal(requests[0].path,'/api/pipelines');
  assert.equal(requests[0].options.method,'POST');
  const payload=JSON.parse(requests[0].options.body);
  assert.equal(payload.driver,'vmxnet3');
  assert.equal(payload.max_duration_minutes,180);
  assert.equal(payload.auto_seed,true);
  assert.equal(payload.extra_enabled,false);
  assert.equal(button.disabled,false);
  context.state.launchTarget=null;
  await get('#launch-form').onsubmit(event);
  assert.equal(requests.length,1);
  assert.match(error,/选择驱动/);
  context.state.launchTarget={driver:'vmxnet3'};
  context.api=async()=>{throw Error('服务器拒绝重复任务')};
  await get('#launch-form').onsubmit(event);
  assert.equal(button.disabled,false);
  assert.match(error,/重复任务/);
  console.log('PASS: frontend POST payload, missing target, error feedback, submit unlock');
}
main().catch(e=>{console.error(e);process.exitCode=1});
