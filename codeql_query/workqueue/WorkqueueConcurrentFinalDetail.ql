/**
 * @name Linux workqueue concurrent free/use candidates - per real use
 * @description Reports one row per concrete callback field, dereference,
 *              array, or known memory-API use covered by a whole-holder or
 *              subobject free. Results remain audit candidates.
 * @kind table
 * @id cpp/linux/workqueue-concurrent-free-use-final-detail
 */

import cpp
import KernelWorkqueueConcurrentFinal

from
  LinuxWorkInit init,
  LinuxWorkEnqueue enq,
  KernelContainerOfRecover rec,
  KernelFreeCall free,
  Expr holderRoot,
  Expr realUse,
  string freePath,
  string freePathKind,
  string usePath,
  string useKind,
  string pathRelation,
  string callDepth,
  string matchKind,
  int callbackCallDepth,
  Location useLocation
where
  queueAndInitHolderCompatible(init, enq, rec) and
  freeAccessPath(free, rec, holderRoot, freePath, _, freePathKind) and
  callbackUseCoveredByFree(
    free, rec, holderRoot, realUse,
    freePath, freePathKind, usePath, useKind,
    callbackCallDepth, pathRelation
  ) and
  (
    queueHolderFlowsToFreeRoot(init, enq, rec, holderRoot) and
    callerChainDepth(enq, free, callDepth) and
    matchKind = "strict_caller_chain"
    or
    free.getEnclosingFunctionSafe() != rec.getRecoverFunction() and
    callDepth = "cross_entry" and
    matchKind = "cross_entry_runtime_identity_not_proved"
  ) and
  useLocation = realUse.getLocation()
select
  "workqueue" as concurrency_model,
  "concurrent_free_real_use" as query_pattern,
  matchKind as match_kind,
  "whole_holder_or_subobject_real_use" as match_basis,

  enq.getFilePath() as lifecycle_file,
  enq.getLocation().getStartLine() as lifecycle_line,
  enq.getEnclosingFunctionSafe().getName() as lifecycle_function,
  enq.getApiName() as lifecycle_api,
  init.getWorkKind() as lifecycle_kind,
  enq.getWorkArgText() as lifecycle_argument,
  init.getWorkExprText() as lifecycle_binding,
  callbackCallDepth as lifecycle_to_callback_depth,
  callDepth as lifecycle_to_free_depth,

  init.getFilePath() as setup_file,
  init.getLocation().getStartLine() as setup_line,
  init.getEnclosingFunctionSafe().getName() as setup_function,
  init.getMacroName() as setup_api,
  init.getCallbackText() as setup_binding,

  rec.getRecoverFunctionName() as callback_entry,
  rec.getRecoverFunctionName() as callback_function,
  rec.getFilePath() as callback_file,
  rec.getLocation().getStartLine() as callback_line,
  init.getWorkKind() as callback_kind,
  "container_of:" + rec.getFieldText() as callback_recovery,
  callbackCallDepth as callback_call_depth,

  free.getEnclosingFunctionSafe().getName() as holder_function,
  holderRoot.toString() as holder_root,
  "recovered_container_holder" as holder_root_kind,
  rec.getHolderTypeText() as holder_type,
  rec.getFieldText() as callback_data_path,

  free.getFilePath() as free_file,
  free.getLocation().getStartLine() as free_line,
  free.getEnclosingFunctionSafe().getName() as free_function,
  free.getApiName() as free_api,
  free.getFreeKind() as free_kind,
  free.getFreedArgText() as freed_expression,
  freePath as freed_object_path,
  freePathKind as freed_path_kind,
  callDepth as free_call_depth,

  realUse.getFile().getRelativePath() as use_file,
  useLocation.getStartLine() as use_line,
  realUse.getEnclosingFunction().getName() as use_function,
  realUse.toString() as use_expression,
  useKind as use_kind,
  usePath as used_object_path,
  pathRelation as path_relation,

  protectionTagForFree(free) as protection_tag,
  "yes=sync cancel/disable or drain/destroy before free; unknown=flush only; no=no modeled work barrier. Verify that it targets the same work item or queue." as protection_detail,
  barrierSummaryForFree(free) as barrier_context,
  "allocation_boundary_requires_review" as allocation_boundary_context,
  "Candidate only: verify runtime object identity, allocation boundaries, ordering, and work cancellation/flush synchronization." as review_boundary,

  rec.getFilePath() as auxiliary_file,
  rec.getLocation().getStartLine() as auxiliary_line,
  rec.getRecoverFunctionName() as auxiliary_function,
  rec.getBaseExprText() as auxiliary_expression

