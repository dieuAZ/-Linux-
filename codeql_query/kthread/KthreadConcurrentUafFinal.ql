/**
 * @name Linux kthread concurrent free/use candidates - final real-use model
 * @description Finds explicit immediate frees that share a holder/root with a
 *              kthread data argument and reports only concrete thread-side
 *              field, dereference, array, or known memory-API accesses on the
 *              freed path or its descendants. Results are audit candidates,
 *              not proof of a vulnerability.
 * @kind table
 * @id cpp/linux/kthread-concurrent-uaf-final-real-use
 */

import cpp
import kthread.kthread_reachable_data_access_v7
import kthread.thread_real_access_v4_1

class KthreadQuiesceCallFinal extends FunctionCall {
  KthreadQuiesceCallFinal() {
    this.getTarget().hasName("kthread_stop") or
    this.getTarget().hasName("kthread_park") or
    this.getTarget().hasName("kthread_flush_worker") or
    this.getTarget().hasName("kthread_destroy_worker")
  }

  string getApiName() { result = this.getTarget().getName() }

  string getStrength() {
    (
      this.getTarget().hasName("kthread_stop") or
      this.getTarget().hasName("kthread_park") or
      this.getTarget().hasName("kthread_destroy_worker")
    ) and result = "strong"
    or
    this.getTarget().hasName("kthread_flush_worker") and result = "weak"
  }
}

predicate quiesceLexicallyBeforeFreeFinal(
  KthreadQuiesceCallFinal quiesce, FreeLikeSink sink
) {
  quiesce.getEnclosingFunction() = sink.getEnclosingFunction() and
  (
    quiesce.getLocation().getStartLine() < sink.getLocation().getStartLine()
    or
    quiesce.getLocation().getStartLine() = sink.getLocation().getStartLine() and
    quiesce.getLocation().getStartColumn() < sink.getLocation().getStartColumn()
  )
}

string kthreadQuiesceContextFinal(FreeLikeSink sink) {
  exists(KthreadQuiesceCallFinal quiesce |
    quiesceLexicallyBeforeFreeFinal(quiesce, sink) and
    result = quiesce.getStrength() + "_quiesce_before_free:" + quiesce.getApiName()
  )
  or
  not exists(KthreadQuiesceCallFinal quiesce |
    quiesceLexicallyBeforeFreeFinal(quiesce, sink)
  ) and result = "no_modeled_quiesce_before_free_same_function"
}

string kthreadProtectionTagFinal(FreeLikeSink sink) {
  exists(KthreadQuiesceCallFinal quiesce |
    quiesceLexicallyBeforeFreeFinal(quiesce, sink) and
    quiesce.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(KthreadQuiesceCallFinal quiesce |
    quiesceLexicallyBeforeFreeFinal(quiesce, sink) and
    quiesce.getStrength() = "strong"
  ) and
  exists(KthreadQuiesceCallFinal quiesce |
    quiesceLexicallyBeforeFreeFinal(quiesce, sink) and
    quiesce.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(KthreadQuiesceCallFinal quiesce |
    quiesceLexicallyBeforeFreeFinal(quiesce, sink)
  ) and result = "no"
}

predicate expressionContainsPointerFieldFinal(Expr e) {
  exists(FieldAccess fa, PointerType pt |
    fa = e.getUnconverted() and
    pt = fa.getTarget().getType().getUnspecifiedType()
  )
  or
  exists(FieldAccess outer |
    outer = e.getUnconverted() and
    expressionContainsPointerFieldFinal(outer.getQualifier())
  )
  or
  exists(PointerDereferenceExpr deref |
    deref = e.getUnconverted() and
    expressionContainsPointerFieldFinal(deref.getOperand())
  )
  or
  exists(ArrayExpr array |
    array = e.getUnconverted() and
    expressionContainsPointerFieldFinal(array.getArrayBase())
  )
}

string allocationBoundaryContextFinal(Expr access) {
  expressionContainsPointerFieldFinal(access) and
  result = "visible_pointer_field_boundary_review_required"
  or
  not expressionContainsPointerFieldFinal(access) and
  result = "no_pointer_field_visible_in_use_expression"
}

from
  FreeLikeSink sink,
  Function holder,
  KthreadStartCallV4 start,
  Variable holderRoot,
  Function entry,
  Function threadFunction,
  Expr access,
  string dataPath,
  string freePath,
  string accessPath,
  string useKind,
  int holderToStartDepth,
  int holderToFreeDepth,
  Location sinkLocation,
  Location startLocation,
  Location accessLocation
where
  kthreadCandidateAccessV4(
    sink, holder, start, holderRoot, threadFunction, access,
    dataPath, freePath, accessPath, useKind,
    holderToStartDepth, holderToFreeDepth
  ) and
  /* Preserve the original model: the lifecycle holder contains the start. */
  holder = start.getEnclosingFunction() and
  entry = threadEntryV4(start) and
  sinkLocation = sink.getLocation() and
  startLocation = start.getLocation() and
  accessLocation = access.getLocation()
select
  "kthread" as concurrency_model,
  "concurrent_free_real_use" as query_pattern,
  "real_use_detail" as match_kind,
  "same_or_descendant_freed_path" as match_basis,

  start.getFile().getRelativePath() as lifecycle_file,
  startLocation.getStartLine() as lifecycle_line,
  start.getEnclosingFunction().getName() as lifecycle_function,
  kthreadSourceStartApiV4(start) as lifecycle_api,
  kthreadStartKindV4(start) as lifecycle_kind,
  start.toString() as lifecycle_argument,
  entry.getName() as lifecycle_binding,
  holderToStartDepth as lifecycle_to_callback_depth,
  holderToFreeDepth as lifecycle_to_free_depth,

  "" as setup_file,
  "" as setup_line,
  "" as setup_function,
  "" as setup_api,
  "" as setup_binding,

  entry.getName() as callback_entry,
  threadFunction.getName() as callback_function,
  entry.getFile().getRelativePath() as callback_file,
  entry.getLocation().getStartLine() as callback_line,
  "kthread_entry" as callback_kind,
  "kthread_data_parameter" as callback_recovery,
  "" as callback_call_depth,

  holder.getName() as holder_function,
  holderRoot.toString() as holder_root,
  holderRootKindV4(holderRoot) as holder_root_kind,
  holderRoot.getType().toString() as holder_type,
  dataPath as callback_data_path,

  sink.getFile().getRelativePath() as free_file,
  sinkLocation.getStartLine() as free_line,
  sink.getEnclosingFunction().getName() as free_function,
  sink.getTarget().getName() as free_api,
  sink.getFreeKind() as free_kind,
  freeObjectArgV4(sink).toString() as freed_expression,
  freePath as freed_object_path,
  "whole_or_subobject; see freed_object_path" as freed_path_kind,
  holderToFreeDepth as free_call_depth,

  access.getFile().getRelativePath() as use_file,
  accessLocation.getStartLine() as use_line,
  threadFunction.getName() as use_function,
  access.toString() as use_expression,
  useKind as use_kind,
  accessPath as used_object_path,
  "same_or_descendant_freed_path" as path_relation,

  kthreadProtectionTagFinal(sink) as protection_tag,
  "yes=stop/park/destroy-worker before free; unknown=flush-worker only; no=no modeled quiesce. Same-function lexical context is not an identity or synchronization proof." as protection_detail,
  kthreadQuiesceContextFinal(sink) as barrier_context,
  allocationBoundaryContextFinal(access) as allocation_boundary_context,
  "Candidate only: verify allocation boundaries, runtime object identity, ordering, and kthread shutdown/synchronization." as review_boundary,

  "" as auxiliary_file,
  "" as auxiliary_line,
  "" as auxiliary_function,
  "" as auxiliary_expression



