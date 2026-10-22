// Regression checks for the task-detail polling path; no server or browser needed.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const app = fs.readFileSync('static/app.js', 'utf8');
const dashboard = fs.readFileSync('static/fuzz-dashboard.js', 'utf8');
const section = (text, start, end) => text.slice(text.indexOf(start), text.indexOf(end));

let detailWrites = 0;
let detailHtml = '';
const root = {
  dataset: {},
  get innerHTML() { return detailHtml; },
  set innerHTML(value) { detailHtml = value; detailWrites += 1; },
  querySelector() { return null; },
};
const log = { textContent: '', scrollHeight: 0, scrollTop: 0, clientHeight: 0 };
const tabs = ['workflow', 'fuzz'].map(name => ({ dataset: {log: name}, classList: {toggle() {}} }));
const nodes = {'#task-detail': root, '#stage-log': log};
const paths = [];
const task = {id: 'task-006', task_type: 'FUZZ', status: 'CANCELLED', stage: 'INTERRUPTED', number: 6,
  linux_version: 'linux-7.1.5', driver: 'saa7134', slug: 'fuzz_linux-7.1.5_saa7134_006', report: {}};
const context = vm.createContext({
  state: {selected: task, detailLog: 'workflow'},
  $: selector => nodes[selector] || {},
  $$: selector => selector === '[data-log]' ? tabs : [],
  esc: String, labelType: String, taskSummary: () => '', fuzzLogMetrics: () => ({}), notice: () => {},
  api: async path => { paths.push(path); if(path.endsWith('/events'))return {items: []};
    if(path.endsWith('/logs/fuzz'))return {content: 'Fuzz log'};
    if(path.endsWith('/logs/workflow'))return {content: 'Workflow log'};
    return task; },
  clearInterval() {}, setInterval() { return 1; },
});
vm.runInContext(section(app, 'function renderDetail(', 'async function taskAction(') +
  section(app, 'async function refreshTask(', 'function fuzzLogMetrics('), context);

async function main() {
  context.renderDetail(task, 'Workflow log', []);
  assert.equal(detailWrites, 1);
  context.renderDetail(task, 'Workflow log', []);
  assert.equal(detailWrites, 1, 'unchanged task must not rebuild its detail');
  await context.loadStageLog(task.id, 'fuzz');
  assert.equal(context.state.detailLog, 'fuzz');
  assert.equal(log.textContent, 'Fuzz log');
  await context.refreshTask(task.id);
  assert.ok(paths.includes('/api/tasks/task-006/logs/fuzz'));
  assert.equal(context.state.detailLog, 'fuzz', 'polling must preserve the selected log tab');
  assert.equal(detailWrites, 1);

  const box = {dataset: {taskId: task.id, renderedHtml: 'same'}, isConnected: true};
  let telemetryRefreshes = 0;
  const dashContext = vm.createContext({
    document: {querySelector: () => box, createElement: () => {throw Error('dashboard was recreated');}},
    renderDetail() {}, refreshFuzzDashboard: () => {telemetryRefreshes += 1;},
    fuzzDashboardHtml: () => 'same',
  });
  vm.runInContext(section(dashboard, 'function renderFuzzDashboard(', 'const baseLoadFuzzPipelines='), dashContext);
  dashContext.renderFuzzDashboard(box, {}, 'detail', task.id);
  dashContext.renderDetail(task, '', []);
  dashContext.renderDetail(task, '', []);
  assert.equal(telemetryRefreshes, 2);
  assert.equal(box.dataset.renderedHtml, 'same', 'unchanged telemetry must not rebuild the dashboard');
  console.log('PASS: unchanged detail/dashboard kept, selected log survives polling');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
