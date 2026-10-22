/**
 * @name Ops bounded object transfer evidence
 * @kind table
 * @id cpp/linux/ops-object-transfer-evidence
 */
import cpp
import ops.OpsObjectFlow
import ops.OpsObjectTransfers
import semmle.code.cpp.dataflow.new.DataFlow

from DataFlow::Node source, string key, string kind, ExprCall dispatch,
  Struct interfaceType, Field method, int index, int steps, string evidence
where
  OpsObjectFlow::origin(source, key, kind) and
  OpsObjectFlow::dispatch(dispatch, interfaceType, method) and
  OpsObjectTransfers::flow(source, DataFlow::exprNode(dispatch.getArgument(index)), steps, evidence) and
  steps > 0
select key as runtime_object_key, method.getName() as method_name,
  dispatch.getFile().getRelativePath() as dispatch_file,
  dispatch.getLocation().getStartLine() as dispatch_line,
  index as argument_index, steps as transfer_count, evidence as transfer_evidence
