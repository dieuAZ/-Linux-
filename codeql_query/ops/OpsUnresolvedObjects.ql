/**
 * @name Ops dispatch pairs with unresolved object identity
 * @description Preserve pairs lacking supported common pointer evidence for later review.
 * @kind table
 * @id cpp/linux/ops-unresolved-objects
 */
import cpp
import ops.OpsModel
import ops.OpsObjectFlow
import semmle.code.cpp.dataflow.new.DataFlow

from Variable instance, Struct interfaceType, Field freeMethod, Field useMethod,
  Function freeFunction, Function useFunction, FunctionCall freeCall,
  FieldAccess useAccess, ExprCall freeDispatch, ExprCall useDispatch
where
  OpsModel::aggregateBinding(instance, interfaceType, freeMethod, freeFunction) and
  OpsModel::aggregateBinding(instance, interfaceType, useMethod, useFunction) and
  freeCall.getEnclosingFunction() = freeFunction and
  freeCall.getTarget().getName() in ["free", "kfree", "kvfree", "vfree", "kfree_sensitive"] and
  useAccess.getEnclosingFunction() = useFunction and
  not freeCall.getAnArgument() = useAccess and
  OpsObjectFlow::dispatch(freeDispatch, interfaceType, freeMethod) and
  OpsObjectFlow::dispatch(useDispatch, interfaceType, useMethod) and
  not exists(DataFlow::Node origin, string key, string kind, int freeIndex, int useIndex,
    int freeDepth, int useDepth, int bindingDepth, int receiverDepthA, int receiverDepthB,
    string freeTrace, string useTrace |
    OpsObjectFlow::origin(origin, key, kind) and
    OpsObjectFlow::reachesArgument(origin, freeDispatch, freeIndex, freeDepth, freeTrace) and
    OpsObjectFlow::reachesArgument(origin, useDispatch, useIndex, useDepth, useTrace) and
    OpsObjectFlow::reachesBinding(origin, instance, bindingDepth) and
    OpsObjectFlow::reachesReceiver(origin, freeDispatch, receiverDepthA) and
    OpsObjectFlow::reachesReceiver(origin, useDispatch, receiverDepthB)
  )
select
  instance.getName() as ops_instance_name,
  instance.getFile().getRelativePath() as ops_instance_file,
  instance.getLocation().getStartLine() as ops_instance_line,
  freeFunction.getQualifiedName() as free_function,
  useFunction.getQualifiedName() as use_function,
  freeDispatch.getFile().getRelativePath() as free_dispatch_file,
  freeDispatch.getLocation().getStartLine() as free_dispatch_line,
  useDispatch.getFile().getRelativePath() as use_dispatch_file,
  useDispatch.getLocation().getStartLine() as use_dispatch_line,
  "unresolved_object_relation" as object_relation,
  "candidate_only_missing_identity_evidence_is_not_disjointness" as review_boundary
