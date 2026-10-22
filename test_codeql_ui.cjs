// Check that the 0922 CodeQL controls do not replace the 1013 task views.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');

const linux = {value: 'linux-7.1.5', innerHTML: ''};
const path = {value: '', innerHTML: ''};
const submit = {disabled: false};
const nodes = {'#codeql-linux': linux, '#codeql-driver': path,
  '#codeql-form button[type=submit]': submit};
let regularFillCalls = 0;
const context = vm.createContext({
  state: {catalogs: {codeql: {'linux-7.1.5': ['.', 'drivers/foo']}}},
  $: selector => nodes[selector],
  esc: String,
  enhanceVersionSelect() {}, syncVersionPicker() {},
  fillSelects() { regularFillCalls += 1; },
  renderLiveCatalog() {}, taskSummary() { return 'ordinary task'; },
});
vm.runInContext(fs.readFileSync('static/codeql-source-ui.js', 'utf8'), context);

context.fillSelects('static');
assert.equal(regularFillCalls, 1);
context.fillSelects('codeql');
assert.match(path.innerHTML, /drivers\/foo/);
assert.equal(submit.disabled, true);
path.value = 'drivers/foo';
path.onchange();
assert.equal(submit.disabled, false);

const summary = context.taskSummary({id: 'task-1', task_type: 'CODEQL_QUERY', status: 'COMPLETED'},
  {codeql_query: {progress: {ops: 'PASSED', llm_review: 'PASSED'}, counts: {ops: 2}}});
assert.match(summary, /ops 查询/);
assert.match(summary, /大模型复核/);
assert.match(summary, /下载最终复核 CSV/);
assert.equal(context.taskSummary({task_type: 'FUZZ'}, {}), 'ordinary task');
console.log('PASS: CodeQL source selection and progress; other task views delegated');
