/**
 * @name Ops free/use candidates with shared runtime object evidence
 * @description Relates callback arguments through dispatch sites and direct wrappers.
 * @kind table
 * @id cpp/linux/ops-concurrent-free-use-paths
 */

import cpp
import ops.OpsModel
import ops.OpsObjectFlow
import ops.OpsCallbackObjects
import concurrency.KernelLifetime
import semmle.code.cpp.dataflow.new.DataFlow

class FreeCall extends FunctionCall {
  FreeCall() {
    exists(Expr object | kernelReleaseObject(this, object)) or
    this.getTarget().hasName("free") or this.getTarget().hasName("kfree") or
    this.getTarget().hasName("kfree_sensitive") or this.getTarget().hasName("kfree_rcu") or
    this.getTarget().hasName("kvfree") or this.getTarget().hasName("vfree") or
    this.getTarget().hasName("kmem_cache_free") or this.getTarget().hasName("mempool_free") or
    this.getTarget().hasName("devm_kfree") or this.getTarget().hasName("kref_put") or
    this.getTarget().hasName("put_device")
  }
}

predicate concreteBinding(
  Variable instance,
  Struct interfaceType,
  Field methodField,
  Function implementation
) {
  OpsModel::aggregateBinding(instance, interfaceType, methodField, implementation)
}

from
  Variable instance,
  Struct interfaceType,
  Field freeField,
  Function freeFunction,
  FunctionCall freeCall,
  Expr freeObject,
  Variable freeRoot,
  int freeRootIndex,
  Field useField,
  Function useFunction,
  FieldAccess useAccess,
  Variable useRoot,
  int useRootIndex,
  string freedPath,
  string usedPath,
  DataFlow::Node origin,
  string objectKey,
  string originKind,
  ExprCall freeDispatch,
  ExprCall useDispatch,
  int freeDepth,
  int useDepth,
  int bindingDepth,
  string freeTrace,
  string useTrace,
  int freeCallbackDepth,
  int useCallbackDepth,
  string argumentValuePath,
  DataFlow::Node receiverOrigin,
  string receiverKey,
  string receiverKind
where
  concreteBinding(instance, interfaceType, freeField, freeFunction) and
  freeFunction.getParameter(freeRootIndex) = freeRoot and
  OpsCallbackObjects::callbackFree(freeFunction, freeRootIndex, freeCall, freeObject,
    freedPath, freeCallbackDepth) and
  not exists(int shorter |
    shorter < freeCallbackDepth and OpsCallbackObjects::callbackFree(freeFunction,
      freeRootIndex, freeCall, freeObject, freedPath, shorter)
  ) and
  concreteBinding(instance, interfaceType, useField, useFunction) and
  useFunction.getParameter(useRootIndex) = useRoot and
  OpsCallbackObjects::callbackUse(useFunction, useRootIndex, useAccess, usedPath, useCallbackDepth) and
  not exists(int shorter |
    shorter < useCallbackDepth and OpsCallbackObjects::callbackUse(useFunction,
      useRootIndex, useAccess, usedPath, shorter)
  ) and
  OpsObjectFlow::dispatch(freeDispatch, interfaceType, freeField) and
  OpsObjectFlow::dispatch(useDispatch, interfaceType, useField) and
  OpsObjectFlow::origin(origin, objectKey, originKind) and
  (
    OpsObjectFlow::reachesArgument(origin, freeDispatch, freeRootIndex, freeDepth, freeTrace) and
    OpsObjectFlow::reachesArgument(origin, useDispatch, useRootIndex, useDepth, useTrace) and
    argumentValuePath = "direct_or_modeled_transfer"
    or
    exists(Parameter root |
      origin = DataFlow::parameterNode(root) and
      OpsCallbackObjects::valueAt(root.getFunction(), root.getIndex(),
        freeDispatch.getArgument(freeRootIndex), argumentValuePath, freeDepth) and
      OpsCallbackObjects::valueAt(root.getFunction(), root.getIndex(),
        useDispatch.getArgument(useRootIndex), argumentValuePath, useDepth) and
      argumentValuePath != "" and
      freeTrace = "root_parameter_to_dispatch_field:" + argumentValuePath and
      useTrace = freeTrace
    )
  ) and
  OpsObjectFlow::origin(receiverOrigin, receiverKey, receiverKind) and
  OpsObjectFlow::reachesBinding(receiverOrigin, instance, bindingDepth) and
  exists(int freeReceiverDepth, int useReceiverDepth |
    OpsObjectFlow::reachesReceiver(receiverOrigin, freeDispatch, freeReceiverDepth) and
    OpsObjectFlow::reachesReceiver(receiverOrigin, useDispatch, useReceiverDepth)
  ) and
  not exists(FreeCall release | release.getAnArgument() = useAccess)
select
  "ops" as concurrency_model,
  "concurrent_free_use_candidate" as query_pattern,
  "shared_pointer_value_at_dispatch" as match_kind,
  interfaceType.getName() + ":" + instance.getFile().getRelativePath() + ":" + instance.getLocation().getStartLine().toString() + ":" + instance.getName() as ops_instance_id,
  interfaceType.getName() as ops_interface_type,
  instance.getName() as ops_instance_name,
  instance.getFile().getRelativePath() as ops_instance_file,
  instance.getLocation().getStartLine() as ops_instance_line,
  freeField.getName() as free_method,
  freeFunction.getQualifiedName() as free_function,
  freeCall.getFile().getRelativePath() as free_file,
  freeCall.getLocation().getStartLine() as free_line,
  freeCall.getTarget().getName() as free_api,
  freeObject.toString() as freed_expression,
  freedPath as freed_object_path,
  freeRootIndex.toString() as free_root_parameter_index,
  useField.getName() as use_method,
  useFunction.getQualifiedName() as use_function,
  useAccess.getFile().getRelativePath() as use_file,
  useAccess.getLocation().getStartLine() as use_line,
  useAccess.toString() as use_expression,
  usedPath as used_object_path,
  useRootIndex.toString() as use_root_parameter_index,
  "may_same_runtime_object" as object_relation,
  "paths_are_context_only" as path_relation,
  "unknown" as execution_context,
  "unknown" as required_locks,
  "unknown" as barriers,
  "candidate_only_verify_overlap_and_lifetime" as review_boundary,
  objectKey as runtime_object_key,
  originKind as object_evidence_kind,
  freeDispatch.getFile().getRelativePath() as free_dispatch_file,
  freeDispatch.getLocation().getStartLine() as free_dispatch_line,
  useDispatch.getFile().getRelativePath() as use_dispatch_file,
  useDispatch.getLocation().getStartLine() as use_dispatch_line,
  freeTrace as free_argument_trace,
  useTrace as use_argument_trace,
  freeDepth as free_wrapper_depth,
  useDepth as use_wrapper_depth,
  freeCallbackDepth as free_callback_depth,
  useCallbackDepth as use_callback_depth,
  "ops_framework_overlap_requires_review" as concurrency_evidence,
  argumentValuePath as dispatch_argument_value_path,
  receiverKey as ops_receiver_object_key
