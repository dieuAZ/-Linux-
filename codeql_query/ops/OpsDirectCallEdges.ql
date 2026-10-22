/**
 * @name Ops resolved direct call edges
 * @description Exports every resolved direct FunctionCall edge with caller and
 *              callee identities plus the call-site location. The caller is always
 *              a function defined in the database; the callee carries its definition
 *              file/line when present (empty/0 when the callee body is outside the
 *              database). Used by Python to assemble call chains without guessing.
 * @kind table
 * @id cpp/linux/ops-direct-call-edges
 */
import cpp

string calleeFile(Function callee) {
  if exists(callee.getDefinition())
  then result = callee.getDefinition().getFile().getRelativePath()
  else result = ""
}

int calleeStart(Function callee) {
  if exists(callee.getDefinition())
  then result = callee.getDefinition().getLocation().getStartLine()
  else result = 0
}

from FunctionCall call, Function caller, Function callee
where
  caller = call.getEnclosingFunction() and
  callee = call.getTarget()
select
  caller.getQualifiedName() as caller_name,
  caller.getLocation().getFile().getRelativePath() as caller_file,
  caller.getLocation().getStartLine() as caller_start_line,
  callee.getQualifiedName() as callee_name,
  callee.getName() as callee_short_name,
  calleeFile(callee) as callee_file,
  calleeStart(callee) as callee_start_line,
  call.getFile().getRelativePath() as call_file,
  call.getLocation().getStartLine() as call_line,
  call.getLocation().getStartColumn() as call_column
