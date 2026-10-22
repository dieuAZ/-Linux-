/** @name Ops free events @kind table @id cpp/linux/ops-free-events */
import cpp
import ops.OpsModel

class FreeCall extends FunctionCall {
  FreeCall() {
    this.getTarget().hasName("free") or this.getTarget().hasName("kfree") or
    this.getTarget().hasName("kfree_sensitive") or this.getTarget().hasName("kfree_rcu") or
    this.getTarget().hasName("kvfree") or this.getTarget().hasName("vfree") or
    this.getTarget().hasName("kmem_cache_free") or this.getTarget().hasName("mempool_free") or
    this.getTarget().hasName("devm_kfree") or this.getTarget().hasName("kref_put") or
    this.getTarget().hasName("put_device")
  }
  Expr objectArgument() { result = this.getArgument(0) }
}

from Variable instance, Struct interfaceType, Field methodField, Function implementation, FreeCall freeCall, Expr freeObject
where
  OpsModel::aggregateBinding(instance, interfaceType, methodField, implementation) and
  freeCall.getEnclosingFunction() = implementation and
  freeObject = freeCall.objectArgument()
select
  interfaceType.getName() + ":" + instance.getFile().getRelativePath() + ":" + instance.getLocation().getStartLine().toString() + ":" + instance.getName() as ops_instance_id,
  interfaceType.getName() as interface_type,
  instance.getFile().getRelativePath() as instance_file,
  instance.getName() as instance_name,
  methodField.getName() as method_name,
  implementation.getQualifiedName() as callback,
  "free" as action,
  freeObject.toString() as object_key,
  "expression_candidate" as object_key_kind,
  "" as may_alias_keys,
  "unknown" as execution_context,
  "unknown" as required_locks,
  "unknown" as barriers,
  freeCall.getFile().getRelativePath() as file,
  freeCall.getLocation().getStartLine() as line,
  freeCall.toString() as expression,
  implementation.getQualifiedName() + ":" + freeCall.getLocation().getStartLine().toString() + ":free" as event_id