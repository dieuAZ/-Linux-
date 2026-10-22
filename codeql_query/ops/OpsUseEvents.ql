/** @name Ops use events @kind table @id cpp/linux/ops-use-events */
import cpp
import ops.OpsModel

predicate pointerUse(FieldAccess access) {
  exists(Expr qualifier |
    qualifier = access.getQualifier()
  )
}

from Variable instance, Struct interfaceType, Field methodField, Function implementation, FieldAccess access
where
  OpsModel::aggregateBinding(instance, interfaceType, methodField, implementation) and
  access.getEnclosingFunction() = implementation and
  pointerUse(access)
select
  interfaceType.getName() + ":" + instance.getFile().getRelativePath() + ":" + instance.getLocation().getStartLine().toString() + ":" + instance.getName() as ops_instance_id,
  interfaceType.getName() as interface_type,
  instance.getFile().getRelativePath() as instance_file,
  instance.getName() as instance_name,
  methodField.getName() as method_name,
  implementation.getQualifiedName() as callback,
  "use" as action,
  access.getQualifier().toString() as object_key,
  "expression_candidate" as object_key_kind,
  "" as may_alias_keys,
  "unknown" as execution_context,
  "unknown" as required_locks,
  "unknown" as barriers,
  access.getFile().getRelativePath() as file,
  access.getLocation().getStartLine() as line,
  access.toString() as expression,
  implementation.getQualifiedName() + ":" + access.getLocation().getStartLine().toString() + ":use" as event_id