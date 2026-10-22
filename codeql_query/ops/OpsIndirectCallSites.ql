/**
 * @name Ops unresolved indirect call sites
 * @description Exports every function-pointer call whose target is not statically
 *              resolved. Records the enclosing function, call-site location, the
 *              callee expression, the function-pointer type, the method field name
 *              and the receiver expression when the callee is a field access
 *              (e.g. `obj->ops->release`). These are dispatch candidates, not proof
 *              of a specific target.
 * @kind table
 * @id cpp/linux/ops-indirect-call-sites
 */
import cpp

string methodName(ExprCall call) {
  if call.getExpr().getUnconverted() instanceof FieldAccess
  then result = call.getExpr().getUnconverted().(FieldAccess).getTarget().getName()
  else result = ""
}

string receiverExpr(ExprCall call) {
  if call.getExpr().getUnconverted() instanceof FieldAccess
  then result = call.getExpr().getUnconverted().(FieldAccess).getQualifier().toString()
  else result = call.getExpr().toString()
}

from ExprCall call, Function enclosing
where
  enclosing = call.getEnclosingFunction()
select
  enclosing.getQualifiedName() as enclosing_function,
  enclosing.getLocation().getFile().getRelativePath() as enclosing_file,
  enclosing.getLocation().getStartLine() as enclosing_start_line,
  call.getFile().getRelativePath() as call_file,
  call.getLocation().getStartLine() as call_line,
  call.getLocation().getStartColumn() as call_column,
  call.getExpr().toString() as call_expression,
  call.getExpr().getType().getUnspecifiedType().toString() as callee_type,
  methodName(call) as method_name,
  receiverExpr(call) as receiver_expression
