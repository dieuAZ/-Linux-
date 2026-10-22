/**
 * @name Ops candidate common argument witnesses
 * @kind table
 * @id cpp/linux/ops-candidate-dispatch-witnesses
 */
import cpp
import ops.OpsCandidateEvidence
import ops.OpsObjectFlow
import semmle.code.cpp.dataflow.new.DataFlow

from Variable table, Struct iface, Field ff, Function fn, int fi, FunctionCall release,
  Expr freed, string fp, Field uf, Function un, int ui, FieldAccess use, string up,
  ExprCall fc, ExprCall uc, DataFlow::Node origin, string key, string kind
where
  OpsCandidateEvidence::pair(table, iface, ff, fn, fi, release, freed, fp, uf, un, ui, use, up) and
  fn != un and
  OpsCandidateEvidence::coveredPath(fp, up) and
  OpsCandidateEvidence::dispatchPair(iface, ff, fi, uf, ui, fc, uc) and
  OpsCandidateEvidence::commonArgument(fc, fi, uc, ui, origin) and
  OpsObjectFlow::origin(origin, key, kind)
select table.getName() as ops_table, ff.getName() as free_method, uf.getName() as use_method,
  key as runtime_object_key, fc.getEnclosingFunction().getName() as free_dispatch_function,
  fc.getLocation().getStartLine() as free_dispatch_line,
  uc.getEnclosingFunction().getName() as use_dispatch_function,
  uc.getLocation().getStartLine() as use_dispatch_line
