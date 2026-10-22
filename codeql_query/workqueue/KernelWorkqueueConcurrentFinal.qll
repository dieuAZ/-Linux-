/**
 * Linux workqueue concurrent UAF candidate library.
 *
 * Changes relative to the previous balanced version:
 *   1. INIT_WORK <-> enqueue matching no longer accepts a variable merely named "work".
 *      The enqueue argument must receive its value through real CodeQL local data flow
 *      from an address-of-field expression such as &worker->work.
 *   2. The work member is represented by the real CodeQL Field entity, so fields named
 *      "work" in unrelated structures do not match.
 *   3. Free/use matching is access-path sensitive. A free of a->b covers uses below
 *      a->b, such as a->b->x, but does not cover sibling uses such as a->state.
 *   4. container_of(...) is the exact recovered-holder source. Callback uses are
 *      followed only through bounded explicit calls and same-position parameters.
 *      A bare use(a) call is not itself an alert; a field dereference in a reachable
 *      callee is.
 *
 * Access paths are bounded to four field components. Child-pointer aliases are
 * followed locally and through at most two explicit parameter hops, for example:
 *
 *   child = a->b;
 *   use(child->x);
 *
 * The scope is controlled only by the CodeQL database supplied at runtime.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

/** Work initialization macros. */
class LinuxWorkInit extends MacroInvocation {
  LinuxWorkInit() {
    this.getMacroName() = "INIT_WORK" or
    this.getMacroName() = "INIT_WORK_ONSTACK" or
    this.getMacroName() = "INIT_DELAYED_WORK" or
    this.getMacroName() = "INIT_DELAYED_WORK_ONSTACK" or
    this.getMacroName() = "INIT_DEFERRABLE_WORK" or
    this.getMacroName() = "INIT_RCU_WORK"
  }

  string getWorkExprText() { result = this.getUnexpandedArgument(0) }
  string getCallbackText() { result = this.getUnexpandedArgument(1) }

  string getWorkKind() {
    (
      this.getMacroName() = "INIT_WORK" or
      this.getMacroName() = "INIT_WORK_ONSTACK"
    ) and result = "work_struct"
    or
    (
      this.getMacroName() = "INIT_DELAYED_WORK" or
      this.getMacroName() = "INIT_DELAYED_WORK_ONSTACK" or
      this.getMacroName() = "INIT_DEFERRABLE_WORK"
    ) and result = "delayed_work"
    or
    this.getMacroName() = "INIT_RCU_WORK" and result = "rcu_work"
  }

  string getFilePath() { result = this.getFile().getRelativePath() }
  Function getEnclosingFunctionSafe() { result = this.getEnclosingFunction() }
}

/** Work submission calls. These are the concurrency fork points. */
class LinuxWorkEnqueue extends FunctionCall {
  LinuxWorkEnqueue() {
    this.getTarget().hasName("queue_work") or
    this.getTarget().hasName("schedule_work") or
    this.getTarget().hasName("queue_work_on") or
    this.getTarget().hasName("schedule_work_on") or
    this.getTarget().hasName("queue_delayed_work") or
    this.getTarget().hasName("schedule_delayed_work") or
    this.getTarget().hasName("mod_delayed_work") or
    this.getTarget().hasName("queue_delayed_work_on") or
    this.getTarget().hasName("mod_delayed_work_on") or
    this.getTarget().hasName("queue_rcu_work")
  }

  Expr getWorkArg() {
    this.getTarget().hasName("queue_work") and result = this.getArgument(1)
    or
    this.getTarget().hasName("schedule_work") and result = this.getArgument(0)
    or
    this.getTarget().hasName("queue_work_on") and result = this.getArgument(2)
    or
    this.getTarget().hasName("schedule_work_on") and result = this.getArgument(1)
    or
    this.getTarget().hasName("queue_delayed_work") and result = this.getArgument(1)
    or
    this.getTarget().hasName("schedule_delayed_work") and result = this.getArgument(0)
    or
    this.getTarget().hasName("mod_delayed_work") and result = this.getArgument(1)
    or
    this.getTarget().hasName("queue_delayed_work_on") and result = this.getArgument(2)
    or
    this.getTarget().hasName("mod_delayed_work_on") and result = this.getArgument(2)
    or
    this.getTarget().hasName("queue_rcu_work") and result = this.getArgument(1)
  }

  string getApiName() { result = this.getTarget().getName() }
  string getWorkArgText() { result = this.getWorkArg().toString() }
  string getFilePath() { result = this.getFile().getRelativePath() }
  Function getEnclosingFunctionSafe() { result = this.getEnclosingFunction() }
}

/** container_of(...) inside a workqueue callback. */
class KernelContainerOfRecover extends MacroInvocation {
  KernelContainerOfRecover() { this.getMacroName() = "container_of" }

  string getBaseExprText() { result = this.getUnexpandedArgument(0) }
  string getHolderTypeText() { result = this.getUnexpandedArgument(1) }
  string getFieldText() { result = this.getUnexpandedArgument(2) }
  Function getRecoverFunction() { result = this.getEnclosingFunction() }
  string getRecoverFunctionName() { result = this.getRecoverFunction().getName() }
  string getFilePath() { result = this.getFile().getRelativePath() }

  /** container_of expands to a complete expression in the Linux kernel. */
  Expr getRecoveredHolderExpr() { result = this.getExpr() }
}

predicate immediateWorkqueueFreeArgument(Function target, int argumentIndex, string freeKind) {
  target.hasName("kfree") and argumentIndex = 0 and freeKind = "heap"
  or target.hasName("kfree_sensitive") and argumentIndex = 0 and freeKind = "heap_sensitive"
  or target.hasName("kfree_const") and argumentIndex = 0 and freeKind = "heap_or_const"
  or target.hasName("kzfree") and argumentIndex = 0 and freeKind = "heap_zeroed"
  or target.hasName("kvfree") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc"
  or target.hasName("kvfree_sensitive") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc_sensitive"
  or target.hasName("vfree") and argumentIndex = 0 and freeKind = "vmalloc"
  or target.hasName("vfree_atomic") and argumentIndex = 0 and freeKind = "vmalloc_atomic"
  or target.hasName("devm_kfree") and argumentIndex = 1 and freeKind = "device_managed_heap"
  or target.hasName("kmem_cache_free") and argumentIndex = 1 and freeKind = "slab_cache"
  or target.hasName("mempool_free") and argumentIndex = 0 and freeKind = "mempool"
  or target.hasName("free_percpu") and argumentIndex = 0 and freeKind = "percpu"
  or target.hasName("dma_free_coherent") and argumentIndex = 2 and freeKind = "dma_coherent"
  or target.hasName("dma_free_attrs") and argumentIndex = 2 and freeKind = "dma_attrs"
  or target.hasName("dma_free_noncoherent") and argumentIndex = 2 and freeKind = "dma_noncoherent"
  or target.hasName("dmam_free_coherent") and argumentIndex = 2 and freeKind = "device_managed_dma"
  or target.hasName("dma_pool_free") and argumentIndex = 1 and freeKind = "dma_pool"
  or target.hasName("pci_free_consistent") and argumentIndex = 2 and freeKind = "pci_consistent"
  or target.hasName("pci_pool_free") and argumentIndex = 1 and freeKind = "pci_pool"
  or target.hasName("usb_free_coherent") and argumentIndex = 2 and freeKind = "usb_coherent"
  or target.hasName("gen_pool_free") and argumentIndex = 1 and freeKind = "generic_pool"
  or target.hasName("free_pages") and argumentIndex = 0 and freeKind = "pages"
  or target.hasName("free_pages_exact") and argumentIndex = 0 and freeKind = "pages_exact"
  or target.hasName("__free_pages") and argumentIndex = 0 and freeKind = "pages_internal"
  or target.hasName("__free_page") and argumentIndex = 0 and freeKind = "page_internal"
  or target.hasName("free_page") and argumentIndex = 0 and freeKind = "page"
  or target.hasName("page_frag_free") and argumentIndex = 0 and freeKind = "page_frag"
  or target.hasName("free_netdev") and argumentIndex = 0 and freeKind = "netdev"
  or target.hasName("hci_free_dev") and argumentIndex = 0 and freeKind = "hci_dev"
  or target.hasName("usb_free_urb") and argumentIndex = 0 and freeKind = "usb_urb"
  or target.hasName("kfree_skb") and argumentIndex = 0 and freeKind = "skb"
  or target.hasName("dev_kfree_skb_any") and argumentIndex = 0 and freeKind = "skb"
  or target.hasName("consume_skb") and argumentIndex = 0 and freeKind = "skb"
  or target.hasName("kmem_cache_free_bulk") and argumentIndex = 2 and freeKind = "slab_cache_bulk"
  or target.hasName("kfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_heap"
  or target.hasName("kvfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_vm"
}

/** Immediate free-like calls. */
class KernelFreeCall extends FunctionCall {
  KernelFreeCall() {
    exists(int argumentIndex, string freeKind |
      immediateWorkqueueFreeArgument(this.getTarget(), argumentIndex, freeKind) and
      argumentIndex < this.getNumberOfArguments()
    )
  }

  int getFreedArgumentIndex() {
    immediateWorkqueueFreeArgument(this.getTarget(), result, _)
  }

  Expr getFreedArg() { result = this.getArgument(this.getFreedArgumentIndex()) }

  string getApiName() { result = this.getTarget().getName() }
  string getFreeKind() { immediateWorkqueueFreeArgument(this.getTarget(), _, result) }
  string getFreedArgText() { result = this.getFreedArg().toString() }
  string getFreedArgTypeText() { result = this.getFreedArg().getType().toString() }
  string getFilePath() { result = this.getFile().getRelativePath() }
  Function getEnclosingFunctionSafe() { result = this.getEnclosingFunction() }
}

/** Workqueue lifecycle barriers. Used for context output, not filtering. */
class LinuxWorkBarrier extends FunctionCall {
  LinuxWorkBarrier() {
    this.getTarget().hasName("cancel_work_sync") or
    this.getTarget().hasName("cancel_delayed_work_sync") or
    this.getTarget().hasName("disable_work_sync") or
    this.getTarget().hasName("disable_delayed_work_sync") or
    this.getTarget().hasName("flush_work") or
    this.getTarget().hasName("flush_delayed_work") or
    this.getTarget().hasName("flush_workqueue") or
    this.getTarget().hasName("drain_workqueue") or
    this.getTarget().hasName("destroy_workqueue")
  }

  Expr getBarrierArg() { result = this.getArgument(0) }
  string getApiName() { result = this.getTarget().getName() }
  string getBarrierArgText() { result = this.getBarrierArg().toString() }
  Function getEnclosingFunctionSafe() { result = this.getEnclosingFunction() }
  string getStrength() {
    (
      this.getTarget().hasName("cancel_work_sync") or
      this.getTarget().hasName("cancel_delayed_work_sync") or
      this.getTarget().hasName("disable_work_sync") or
      this.getTarget().hasName("disable_delayed_work_sync") or
      this.getTarget().hasName("drain_workqueue") or
      this.getTarget().hasName("destroy_workqueue")
    ) and result = "strong"
    or
    (
      this.getTarget().hasName("flush_work") or
      this.getTarget().hasName("flush_delayed_work") or
      this.getTarget().hasName("flush_workqueue")
    ) and result = "weak"
  }
}

/** Match INIT_WORK callback argument with the callback containing container_of. */
predicate initCallbackMayReferToRecover(LinuxWorkInit init, KernelContainerOfRecover rec) {
  init.getCallbackText() = rec.getRecoverFunctionName()
  or init.getCallbackText() = "&" + rec.getRecoverFunctionName()
  or init.getCallbackText() = "(" + rec.getRecoverFunctionName() + ")"
  or init.getCallbackText() = "(&" + rec.getRecoverFunctionName() + ")"
}
/** Map container_of's type argument to a real user type. */
UserType recoveredHolderType(KernelContainerOfRecover rec) {
  rec.getHolderTypeText() = result.getName()
  or rec.getHolderTypeText() = "struct " + result.getName()
  or rec.getHolderTypeText() = "union " + result.getName()
  or rec.getHolderTypeText() = "class " + result.getName()
}

/**
 * Exact one-level pointer match for the recovered holder type.
 *
 * This intentionally rejects T**, arrays, and unrelated void** containers.
 * Typedefs and const/volatile qualifiers on the pointee are resolved/stripped.
 */
predicate exprHasRecoveredHolderType(Expr e, KernelContainerOfRecover rec) {
  exists(PointerType p |
    e.getUnderlyingType() = p and
    p.getBaseType().stripType() = recoveredHolderType(rec) and
    not exists(PointerType inner |
      p.getBaseType().getUnderlyingType() = inner
    )
  )
}

/** The real member described by container_of(type, member). */
Field recoveredWorkField(KernelContainerOfRecover rec) {
  result.getName() = rec.getFieldText() and
  result.getDeclaringType().stripType() = recoveredHolderType(rec)
}

/** Value-preserving local data flow. */
predicate localValueFlow(Expr sourceExpr, Expr sinkExpr) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    source.asExpr() = sourceExpr and
    sink.asExpr() = sinkExpr and
    DataFlow::localFlow(source, sink)
  )
}

/**
 * Recognize an expression that denotes the address of a real field.
 * The holder is the qualifier before the final member access.
 */
predicate addressOfFieldExpr(Expr e, Field f, Expr holder) {
  exists(AddressOfExpr addr, FieldAccess fa |
    e.getUnconverted() = addr and
    addr.getOperand().getUnconverted() = fa and
    f = fa.getTarget() and
    holder = fa.getQualifier().getUnconverted()
  )
}

/**
 * Resolve the actual source of an enqueue argument using local data flow.
 *
 * Examples accepted:
 *   queue_work(wq, &worker->work)
 *   work = &worker->work; queue_work(wq, work)
 *
 * A standalone variable merely named "work" is not accepted unless a real
 * address-of-field value flows into it.
 */
predicate enqueueWorkFieldSource(
  LinuxWorkEnqueue enq,
  Field f,
  Expr holder,
  Expr sourceExpr
) {
  addressOfFieldExpr(sourceExpr, f, holder) and
  sourceExpr.getEnclosingFunction() = enq.getEnclosingFunctionSafe() and
  sourceExpr.getLocation().getStartLine() <= enq.getLocation().getStartLine() and
  localValueFlow(sourceExpr, enq.getWorkArg())
}

/**
 * Bridge INIT_WORK's macro argument to the real Field entity.
 *
 * Macro arguments are exposed as strings by CodeQL. The preferred branch uses
 * an AST FieldAccess affected by this exact macro invocation. The second branch
 * is a conservative bridge for extractor versions that do not expose that
 * argument FieldAccess directly; it is still constrained by callback identity,
 * recovered holder type, and the real Field entity.
 */
predicate initTargetsRecoveredField(
  LinuxWorkInit init,
  KernelContainerOfRecover rec,
  Field f
) {
  f = recoveredWorkField(rec) and
  (
    exists(FieldAccess fa |
      fa.getTarget() = f and
      fa = init.getAnAffectedElement()
    )
    or
    init.getWorkExprText().matches("%->" + f.getName())
    or init.getWorkExprText().matches("%." + f.getName())
  )
}

/** Real data-flow/field-sensitive INIT_WORK <-> enqueue pairing. */
predicate queueAndInitHolderCompatible(
  LinuxWorkInit init,
  LinuxWorkEnqueue enq,
  KernelContainerOfRecover rec
) {
  initCallbackMayReferToRecover(init, rec) and
  exists(Field f, Expr holder, Expr sourceExpr |
    initTargetsRecoveredField(init, rec, f) and
    enqueueWorkFieldSource(enq, f, holder, sourceExpr) and
    exprHasRecoveredHolderType(holder, rec)
  )
}

Expr queueHolderExpr(
  LinuxWorkInit init,
  LinuxWorkEnqueue enq,
  KernelContainerOfRecover rec
) {
  exists(Field f, Expr sourceExpr |
    initTargetsRecoveredField(init, rec, f) and
    enqueueWorkFieldSource(enq, f, result, sourceExpr) and
    exprHasRecoveredHolderType(result, rec)
  )
}

string queueSourceExprText(
  LinuxWorkInit init,
  LinuxWorkEnqueue enq,
  KernelContainerOfRecover rec
) {
  exists(Field f, Expr holder, Expr sourceExpr |
    initTargetsRecoveredField(init, rec, f) and
    enqueueWorkFieldSource(enq, f, holder, sourceExpr) and
    result = sourceExpr.toString()
  )
}

/* ------------------------------------------------------------------------- */
/* Bounded structural access paths                                           */
/* ------------------------------------------------------------------------- */

/**
 * A syntactic field path rooted at root, bounded to four fields.
 * Paths are generated from real FieldAccess/Field entities, not by scanning
 * arbitrary text. Examples: .b, .b.child, .b.child.value.
 */
predicate fieldPathFromRoot(
  Expr root,
  FieldAccess leaf,
  string path,
  int depth
) {
  leaf.getQualifier().getUnconverted() = root.getUnconverted() and
  path = "." + leaf.getTarget().getName() and depth = 1
  or
  exists(FieldAccess f1 |
    leaf.getQualifier().getUnconverted() = f1 and
    f1.getQualifier().getUnconverted() = root.getUnconverted() and
    path = "." + f1.getTarget().getName() + "." + leaf.getTarget().getName() and
    depth = 2
  )
  or
  exists(FieldAccess f1, FieldAccess f2 |
    leaf.getQualifier().getUnconverted() = f2 and
    f2.getQualifier().getUnconverted() = f1 and
    f1.getQualifier().getUnconverted() = root.getUnconverted() and
    path = "." + f1.getTarget().getName() + "." + f2.getTarget().getName() +
      "." + leaf.getTarget().getName() and
    depth = 3
  )
  or
  exists(FieldAccess f1, FieldAccess f2, FieldAccess f3 |
    leaf.getQualifier().getUnconverted() = f3 and
    f3.getQualifier().getUnconverted() = f2 and
    f2.getQualifier().getUnconverted() = f1 and
    f1.getQualifier().getUnconverted() = root.getUnconverted() and
    path = "." + f1.getTarget().getName() + "." + f2.getTarget().getName() +
      "." + f3.getTarget().getName() + "." + leaf.getTarget().getName() and
    depth = 4
  )
}

/* ------------------------------------------------------------------------- */
/* container_of holder -> callback-reachable roots                           */
/* ------------------------------------------------------------------------- */

/**
 * A local expression whose value comes from this exact container_of result.
 * This is the only callback-holder source used by the callback-side analysis.
 */
predicate recoveredHolderLocalRoot(
  KernelContainerOfRecover rec,
  Expr root
) {
  root.getEnclosingFunction() = rec.getRecoverFunction() and
  localValueFlow(rec.getRecoveredHolderExpr(), root) and
  exprHasRecoveredHolderType(root, rec)
}

/**
 * Map a value at a call argument to the corresponding callee parameter, then
 * allow local aliases of that parameter inside the callee.
 */
predicate holderFlowsThroughDirectCall(
  KernelContainerOfRecover rec,
  Expr callerRoot,
  FunctionCall call,
  int argumentIndex,
  Expr calleeRoot
) {
  call.getEnclosingFunction() = callerRoot.getEnclosingFunction() and
  localValueFlow(callerRoot, call.getArgument(argumentIndex)) and
  exists(Parameter p, VariableAccess parameterAccess |
    p = call.getTarget().getParameter(argumentIndex) and
    parameterAccess = p.getAnAccess() and
    calleeRoot.getEnclosingFunction() = call.getTarget() and
    localValueFlow(parameterAccess, calleeRoot) and
    exprHasRecoveredHolderType(calleeRoot, rec)
  )
}

/**
 * Holder roots reachable from the callback by a bounded, explicit call chain.
 *
 * This replaces unrestricted global data flow. Every interprocedural step must
 * be a real FunctionCall, the holder value must reach a concrete argument, and
 * that argument must map to the same positional parameter in the callee.
 */
predicate recoveredHolderRootAtDepth(
  KernelContainerOfRecover rec,
  Expr root,
  int callDepth
) {
  recoveredHolderLocalRoot(rec, root) and callDepth = 0
  or
  exists(Expr r0, FunctionCall c1, int i1 |
    recoveredHolderLocalRoot(rec, r0) and
    holderFlowsThroughDirectCall(rec, r0, c1, i1, root) and
    callDepth = 1
  )
  or
  exists(Expr r0, Expr r1,
         FunctionCall c1, FunctionCall c2,
         int i1, int i2 |
    recoveredHolderLocalRoot(rec, r0) and
    holderFlowsThroughDirectCall(rec, r0, c1, i1, r1) and
    holderFlowsThroughDirectCall(rec, r1, c2, i2, root) and
    callDepth = 2
  )
  or
  exists(Expr r0, Expr r1, Expr r2,
         FunctionCall c1, FunctionCall c2, FunctionCall c3,
         int i1, int i2, int i3 |
    recoveredHolderLocalRoot(rec, r0) and
    holderFlowsThroughDirectCall(rec, r0, c1, i1, r1) and
    holderFlowsThroughDirectCall(rec, r1, c2, i2, r2) and
    holderFlowsThroughDirectCall(rec, r2, c3, i3, root) and
    callDepth = 3
  )
}

/** A direct child/subtree expression rooted in a callback-reachable holder. */
predicate recoveredDirectFieldExpr(
  KernelContainerOfRecover rec,
  FieldAccess fieldExpr,
  string path,
  int pathDepth,
  int holderCallDepth
) {
  exists(Expr root |
    recoveredHolderRootAtDepth(rec, root, holderCallDepth) and
    fieldPathFromRoot(root, fieldExpr, path, pathDepth)
  )
}

/**
 * Generic explicit argument-to-parameter transfer for a child pointer value.
 * No global flow, global variables, or unrelated callers are admitted.
 */
predicate childFlowsThroughDirectCall(
  Expr callerRoot,
  FunctionCall call,
  int argumentIndex,
  Expr calleeRoot
) {
  call.getEnclosingFunction() = callerRoot.getEnclosingFunction() and
  localValueFlow(callerRoot, call.getArgument(argumentIndex)) and
  exists(Parameter p, VariableAccess parameterAccess |
    p = call.getTarget().getParameter(argumentIndex) and
    parameterAccess = p.getAnAccess() and
    calleeRoot.getEnclosingFunction() = call.getTarget() and
    localValueFlow(parameterAccess, calleeRoot)
  )
}

/**
 * Bounded aliases of a recovered-holder child pointer.
 *
 * Supported:
 *   child = holder->b; child->x
 *   helper(holder->b); helper's parameter -> x
 *   one additional direct parameter hop
 */
predicate recoveredChildAliasRootAtDepth(
  FieldAccess prefix,
  Expr aliasRoot,
  int aliasCallDepth
) {
  prefix.getEnclosingFunction() = aliasRoot.getEnclosingFunction() and
  prefix != aliasRoot and
  localValueFlow(prefix, aliasRoot) and
  aliasCallDepth = 0
  or
  exists(FunctionCall c1, int i1 |
    childFlowsThroughDirectCall(prefix, c1, i1, aliasRoot) and
    aliasCallDepth = 1
  )
  or
  exists(Expr r1,
         FunctionCall c1, FunctionCall c2,
         int i1, int i2 |
    childFlowsThroughDirectCall(prefix, c1, i1, r1) and
    childFlowsThroughDirectCall(r1, c2, i2, aliasRoot) and
    aliasCallDepth = 2
  )
}

/**
 * Actual callback-side field dereference path.
 *
 * All roots originate from this exact container_of expression, and all
 * interprocedural uses are restricted to a direct callback-reachable call
 * chain of at most three holder-parameter hops. Child aliases use only local
 * flow plus at most two explicit parameter hops.
 */
predicate callbackFieldUsePath(
  KernelContainerOfRecover rec,
  FieldAccess use,
  string path,
  string useKind,
  int callbackCallDepth
) {
  exists(Expr root, int pathDepth |
    recoveredHolderRootAtDepth(rec, root, callbackCallDepth) and
    fieldPathFromRoot(root, use, path, pathDepth) and
    useKind = "holder_direct_or_parameter"
  )
  or
  exists(
    FieldAccess prefix, Expr aliasRoot,
    string prefixPath, string suffixPath,
    int prefixDepth, int suffixDepth,
    int holderDepth, int aliasDepth
  |
    recoveredDirectFieldExpr(
      rec, prefix, prefixPath, prefixDepth, holderDepth
    ) and
    recoveredChildAliasRootAtDepth(prefix, aliasRoot, aliasDepth) and
    fieldPathFromRoot(aliasRoot, use, suffixPath, suffixDepth) and
    prefixDepth + suffixDepth <= 4 and
    path = prefixPath + suffixPath and
    callbackCallDepth = holderDepth + aliasDepth and
    useKind = "child_alias_bounded_direct_calls"
  )
}

predicate workqueueMemoryApiArgUse(FunctionCall call, int argIndex) {
  (
    call.getTarget().hasName("memcpy") or
    call.getTarget().hasName("memmove") or
    call.getTarget().hasName("memcmp") or
    call.getTarget().hasName("memcpy_toio") or
    call.getTarget().hasName("memcpy_fromio") or
    call.getTarget().hasName("strcmp") or
    call.getTarget().hasName("strncmp") or
    call.getTarget().hasName("strcpy") or
    call.getTarget().hasName("strncpy") or
    call.getTarget().hasName("strscpy") or
    call.getTarget().hasName("strscpy_pad") or
    call.getTarget().hasName("strlcpy") or
    call.getTarget().hasName("strcat") or
    call.getTarget().hasName("strncat")
  ) and (argIndex = 0 or argIndex = 1)
  or
  (
    call.getTarget().hasName("memset") or
    call.getTarget().hasName("memzero_explicit") or
    call.getTarget().hasName("strlen") or
    call.getTarget().hasName("strnlen") or
    call.getTarget().hasName("strchr") or
    call.getTarget().hasName("strrchr") or
    call.getTarget().hasName("strnchr") or
    call.getTarget().hasName("memchr") or
    call.getTarget().hasName("kmemdup") or
    call.getTarget().hasName("kmemdup_nul")
  ) and argIndex = 0
  or call.getTarget().hasName("copy_to_user") and argIndex = 1
  or call.getTarget().hasName("copy_from_user") and argIndex = 0
}

predicate workqueueFieldCoveredBySpecificUse(FieldAccess field) {
  exists(PointerDereferenceExpr deref |
    deref.getOperand().getUnconverted() = field.getUnconverted()
  )
  or
  exists(ArrayExpr array |
    array.getArrayBase().getUnconverted() = field.getUnconverted()
  )
  or
  exists(FunctionCall call, int i |
    workqueueMemoryApiArgUse(call, i) and
    call.getArgument(i).getUnconverted() = field.getUnconverted()
  )
}

/** Path of either a field expression, the recovered holder, or a child alias. */
predicate callbackTrackedExprPath(
  KernelContainerOfRecover rec,
  Expr expr,
  string path,
  string originKind,
  int callbackCallDepth
) {
  exists(FieldAccess field |
    field = expr.getUnconverted() and
    callbackFieldUsePath(rec, field, path, originKind, callbackCallDepth)
  )
  or
  exists(Expr root |
    recoveredHolderRootAtDepth(rec, root, callbackCallDepth) and
    localValueFlow(root, expr) and
    path = "<holder>" and originKind = "holder_direct_or_parameter"
  )
  or
  exists(
    FieldAccess prefix, string prefixPath,
    int prefixDepth, int holderDepth, int aliasDepth
  |
    recoveredDirectFieldExpr(rec, prefix, prefixPath, prefixDepth, holderDepth) and
    recoveredChildAliasRootAtDepth(prefix, expr, aliasDepth) and
    path = prefixPath and
    callbackCallDepth = holderDepth + aliasDepth and
    originKind = "child_alias_bounded_direct_calls"
  )
}

/** Concrete field/dereference/array/memory-API access in the work callback. */
predicate callbackRealUsePath(
  KernelContainerOfRecover rec,
  Expr use,
  string path,
  string useKind,
  int callbackCallDepth
) {
  exists(FieldAccess field, string originKind |
    use = field and
    callbackFieldUsePath(rec, field, path, originKind, callbackCallDepth) and
    not exists(AddressOfExpr addr |
      addr.getOperand().getUnconverted() = field.getUnconverted()
    ) and
    not exists(FieldAccess outer |
      outer.getQualifier().getUnconverted() = field.getUnconverted()
    ) and
    not workqueueFieldCoveredBySpecificUse(field) and
    (field.isRValue() or field.isModified() or field.isUsedAsLValue()) and
    useKind = "field_access:" + originKind
  )
  or
  exists(PointerDereferenceExpr deref, string originKind |
    use = deref and
    callbackTrackedExprPath(
      rec, deref.getOperand().getUnconverted(), path, originKind, callbackCallDepth
    ) and
    useKind = "deref_access:" + originKind
  )
  or
  exists(ArrayExpr array, string originKind |
    use = array and
    callbackTrackedExprPath(
      rec, array.getArrayBase().getUnconverted(), path, originKind, callbackCallDepth
    ) and
    (array.hasLValueToRValueConversion() or array.isModified()) and
    useKind = "array_access:" + originKind
  )
  or
  exists(FunctionCall call, int i, string originKind |
    use = call and workqueueMemoryApiArgUse(call, i) and
    callbackTrackedExprPath(
      rec, call.getArgument(i).getUnconverted(), path, originKind, callbackCallDepth
    ) and
    useKind = "mem_api_arg_use:" + originKind
  )
}

/* ------------------------------------------------------------------------- */
/* Free access path                                                          */
/* ------------------------------------------------------------------------- */

/** Direct or locally aliased subobject passed to free. */
predicate subobjectFreePath(
  KernelFreeCall free,
  KernelContainerOfRecover rec,
  Expr holderRoot,
  string path,
  int depth,
  string freePathKind
) {
  exists(FieldAccess fieldExpr |
    free.getFreedArg().getUnconverted() = fieldExpr and
    fieldPathFromRoot(holderRoot, fieldExpr, path, depth) and
    exprHasRecoveredHolderType(holderRoot, rec) and
    freePathKind = "direct_subobject"
  )
  or
  exists(FieldAccess fieldExpr, DataFlow::Node source, DataFlow::Node sink |
    fieldPathFromRoot(holderRoot, fieldExpr, path, depth) and
    exprHasRecoveredHolderType(holderRoot, rec) and
    fieldExpr.getEnclosingFunction() = free.getEnclosingFunctionSafe() and
    source.asExpr() = fieldExpr and
    sink.asExpr() = free.getFreedArg() and
    DataFlow::localFlow(source, sink) and
    free.getFreedArg().getUnconverted() != fieldExpr and
    freePathKind = "local_alias_subobject"
  )
}

predicate freeAccessPath(
  KernelFreeCall free,
  KernelContainerOfRecover rec,
  Expr holderRoot,
  string path,
  int depth,
  string freePathKind
) {
  subobjectFreePath(free, rec, holderRoot, path, depth, freePathKind)
  or
  holderRoot = free.getFreedArg().getUnconverted() and
  exprHasRecoveredHolderType(holderRoot, rec) and
  not exists(Expr subRoot, string subPath, int subDepth, string subKind |
    subobjectFreePath(free, rec, subRoot, subPath, subDepth, subKind)
  ) and
  path = "<holder>" and depth = 0 and freePathKind = "whole_holder"
}

/**
 * Tree/subobject coverage semantics are intentionally evaluated inline at
 * each candidate site. In CodeQL, a standalone predicate whose only inputs
 * are strings constrained by matches() is not range-restricted: the compiler
 * cannot assume that its callers have already bound those strings. Keeping
 * the relation inline lets freeAccessPath() and callbackFieldUsePath() provide
 * the finite bindings first.
 *
 * free(a) covers any callback field path rooted in a.
 * free(a->b) covers .b.x, .b.x.y, ... but not .state or .other.
 * The equal path .b is only a read of the pointer field itself and is not
 * treated as a dereference of the freed pointee in this high-confidence query.
 */

/* ------------------------------------------------------------------------- */
/* Strict caller-chain flow                                                  */
/* ------------------------------------------------------------------------- */

predicate callIsAfterQueueSameFunction(LinuxWorkEnqueue enq, FunctionCall call) {
  call.getEnclosingFunction() = enq.getEnclosingFunctionSafe() and
  call.getLocation().getStartLine() > enq.getLocation().getStartLine()
}

predicate callerChainDepth(
  LinuxWorkEnqueue enq,
  KernelFreeCall free,
  string callDepth
) {
  free.getEnclosingFunctionSafe() = enq.getEnclosingFunctionSafe() and
  free.getLocation().getStartLine() > enq.getLocation().getStartLine() and
  callDepth = "0"
  or
  exists(FunctionCall c1 |
    callIsAfterQueueSameFunction(enq, c1) and
    c1.getTarget() = free.getEnclosingFunctionSafe() and
    callDepth = "1"
  )
  or
  exists(FunctionCall c1, FunctionCall c2, Function f1 |
    callIsAfterQueueSameFunction(enq, c1) and c1.getTarget() = f1 and
    c2.getEnclosingFunction() = f1 and
    c2.getTarget() = free.getEnclosingFunctionSafe() and
    callDepth = "2"
  )
  or
  exists(FunctionCall c1, FunctionCall c2, FunctionCall c3, Function f1, Function f2 |
    callIsAfterQueueSameFunction(enq, c1) and c1.getTarget() = f1 and
    c2.getEnclosingFunction() = f1 and c2.getTarget() = f2 and
    c3.getEnclosingFunction() = f2 and
    c3.getTarget() = free.getEnclosingFunctionSafe() and
    callDepth = "3"
  )
}

module QueueHolderToFreeRootConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(LinuxWorkInit init, LinuxWorkEnqueue enq, KernelContainerOfRecover rec |
      queueAndInitHolderCompatible(init, enq, rec) and
      source.asExpr() = queueHolderExpr(init, enq, rec)
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(KernelFreeCall free, KernelContainerOfRecover rec, Expr holderRoot,
           string path, int depth, string freePathKind |
      freeAccessPath(free, rec, holderRoot, path, depth, freePathKind) and
      sink.asExpr() = holderRoot
    )
  }
}

module QueueHolderToFreeRootFlow = DataFlow::Global<QueueHolderToFreeRootConfig>;

predicate queueHolderFlowsToFreeRoot(
  LinuxWorkInit init,
  LinuxWorkEnqueue enq,
  KernelContainerOfRecover rec,
  Expr holderRoot
) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    source.asExpr() = queueHolderExpr(init, enq, rec) and
    sink.asExpr() = holderRoot and
    QueueHolderToFreeRootFlow::flow(source, sink)
  )
}

/**
 * A callback field use covered by a particular whole-holder/subobject free.
 * The access-path relation is evaluated only after both paths are finitely
 * bound by freeAccessPath() and callbackFieldUsePath().
 */
predicate callbackUseCoveredByFree(
  KernelFreeCall free,
  KernelContainerOfRecover rec,
  Expr holderRoot,
  Expr callbackUse,
  string freePath,
  string freePathKind,
  string usePath,
  string useKind,
  int callbackCallDepth,
  string pathRelation
) {
  exists(int freeDepth |
    freeAccessPath(
      free, rec, holderRoot, freePath, freeDepth, freePathKind
    ) and
    callbackRealUsePath(
      rec, callbackUse, usePath, useKind, callbackCallDepth
    ) and
    (
      freePath = "<holder>" and
      (usePath = "<holder>" or usePath.matches(".%")) and
      pathRelation = "whole_holder_covers_real_use"
      or
      freePath != "<holder>" and
      (
        usePath = freePath
        or usePath.matches(freePath + ".%")
      ) and
      pathRelation = "freed_subobject_covers_real_use"
    )
  )
}

/**
 * Number of distinct covered callback access paths for one lifecycle pair.
 *
 * The string parameters must be finitely bound before entering the aggregate.
 * Binding them only inside count(...) is not sufficient for CodeQL's binding
 * analysis, even when the caller has already supplied concrete values.
 */
int coveredCallbackUsePathCount(
  KernelFreeCall free,
  KernelContainerOfRecover rec,
  Expr holderRoot,
  string freePath,
  string freePathKind,
  string pathRelation
) {
  exists(int freeDepth |
    freeAccessPath(
      free, rec, holderRoot, freePath, freeDepth, freePathKind
    ) and
    (
      freePath = "<holder>" and
      pathRelation = "whole_holder_covers_real_use"
      or
      freePath != "<holder>" and
      pathRelation = "freed_subobject_covers_real_use"
    ) and
    result = count(string p |
      exists(Expr callbackUse, string useKind, int callbackCallDepth |
        callbackUseCoveredByFree(
          free, rec, holderRoot, callbackUse,
          freePath, freePathKind, p, useKind,
          callbackCallDepth, pathRelation
        )
      )
    )
  )
}

/**
 * Number of concrete FieldAccess sites covered by the same lifecycle pair.
 * freePath, freePathKind, and pathRelation are bound outside count(...).
 */
int coveredCallbackUseSiteCount(
  KernelFreeCall free,
  KernelContainerOfRecover rec,
  Expr holderRoot,
  string freePath,
  string freePathKind,
  string pathRelation
) {
  exists(int freeDepth |
    freeAccessPath(
      free, rec, holderRoot, freePath, freeDepth, freePathKind
    ) and
    (
      freePath = "<holder>" and
      pathRelation = "whole_holder_covers_real_use"
      or
      freePath != "<holder>" and
      pathRelation = "freed_subobject_covers_real_use"
    ) and
    result = count(Expr callbackUse |
      exists(string usePath, string useKind, int callbackCallDepth |
        callbackUseCoveredByFree(
          free, rec, holderRoot, callbackUse,
          freePath, freePathKind, usePath, useKind,
          callbackCallDepth, pathRelation
        )
      )
    )
  )
}

/** Strict same-caller-chain candidate with global holder-to-free data flow. */
predicate callerPathSensitiveCandidate(
  LinuxWorkInit init,
  LinuxWorkEnqueue enq,
  KernelContainerOfRecover rec,
  KernelFreeCall free,
  string freePath,
  string freePathKind,
  string pathRelation,
  string callDepth,
  int coveredUsePathCount,
  int coveredUseSiteCount
) {
  queueAndInitHolderCompatible(init, enq, rec) and
  exists(Expr holderRoot, int freeDepth |
    freeAccessPath(free, rec, holderRoot, freePath, freeDepth, freePathKind) and
    queueHolderFlowsToFreeRoot(init, enq, rec, holderRoot) and
    callerChainDepth(enq, free, callDepth) and
    exists(Expr witnessUse, string witnessUsePath,
           string witnessUseKind, int witnessCallDepth |
      callbackUseCoveredByFree(
        free, rec, holderRoot, witnessUse,
        freePath, freePathKind, witnessUsePath, witnessUseKind,
        witnessCallDepth, pathRelation
      )
    ) and
    coveredUsePathCount = coveredCallbackUsePathCount(
      free, rec, holderRoot, freePath, freePathKind, pathRelation
    ) and
    coveredUseSiteCount = coveredCallbackUseSiteCount(
      free, rec, holderRoot, freePath, freePathKind, pathRelation
    ) and
    coveredUsePathCount > 0 and
    coveredUseSiteCount > 0
  )
}

/**
 * Cross-entry lifecycle candidate. Runtime identity cannot generally be proved
 * across independent driver entries, so this branch retains the prior
 * same-file restriction. Callback uses are nevertheless source-, call-chain-,
 * field-, and access-path-sensitive. Callback self-free remains excluded.
 */
predicate crossEntryPathSensitiveCandidate(
  LinuxWorkInit init,
  LinuxWorkEnqueue enq,
  KernelContainerOfRecover rec,
  KernelFreeCall free,
  string freePath,
  string freePathKind,
  string pathRelation,
  int coveredUsePathCount,
  int coveredUseSiteCount
) {
  queueAndInitHolderCompatible(init, enq, rec) and
  free.getEnclosingFunctionSafe() != rec.getRecoverFunction() and
  exists(Expr holderRoot, int freeDepth |
    freeAccessPath(free, rec, holderRoot, freePath, freeDepth, freePathKind) and
    exists(Expr witnessUse, string witnessUsePath,
           string witnessUseKind, int witnessCallDepth |
      callbackUseCoveredByFree(
        free, rec, holderRoot, witnessUse,
        freePath, freePathKind, witnessUsePath, witnessUseKind,
        witnessCallDepth, pathRelation
      )
    ) and
    coveredUsePathCount = coveredCallbackUsePathCount(
      free, rec, holderRoot, freePath, freePathKind, pathRelation
    ) and
    coveredUseSiteCount = coveredCallbackUseSiteCount(
      free, rec, holderRoot, freePath, freePathKind, pathRelation
    ) and
    coveredUsePathCount > 0 and
    coveredUseSiteCount > 0
  )
}

/** Barrier summary before free in the same free function. */
string barrierSummaryForFree(KernelFreeCall free) {
  exists(LinuxWorkBarrier b |
    b.getEnclosingFunctionSafe() = free.getEnclosingFunctionSafe() and
    b.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    result = b.getStrength() + "_barrier_before_free:" + b.getApiName() + "(" + b.getBarrierArgText() + ")"
  )
  or
  not exists(LinuxWorkBarrier b |
    b.getEnclosingFunctionSafe() = free.getEnclosingFunctionSafe() and
    b.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "none_in_free_function_before_free"
}

/** Unified yes/unknown/no protection tag for a free site. */
string protectionTagForFree(KernelFreeCall free) {
  exists(LinuxWorkBarrier b |
    b.getEnclosingFunctionSafe() = free.getEnclosingFunctionSafe() and
    b.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    b.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(LinuxWorkBarrier b |
    b.getEnclosingFunctionSafe() = free.getEnclosingFunctionSafe() and
    b.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    b.getStrength() = "strong"
  ) and
  exists(LinuxWorkBarrier b |
    b.getEnclosingFunctionSafe() = free.getEnclosingFunctionSafe() and
    b.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    b.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(LinuxWorkBarrier b |
    b.getEnclosingFunctionSafe() = free.getEnclosingFunctionSafe() and
    b.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "no"
}

