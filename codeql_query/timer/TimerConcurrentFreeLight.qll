import KernelObjectPathFlow
import cpp

predicate hasName(Function f, string name) {
  f.getName() = name or f.hasGlobalName(name)
}

int maxTreeFieldDepth() { result = 3 }
int maxFreeCallDepth() { result = 1 }

class TimerSetupCall extends FunctionCall {
  TimerSetupCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        hasName(f, "timer_setup") or hasName(f, "timer_setup_on_stack") or
        hasName(f, "__timer_init") or hasName(f, "__timer_init_on_stack") or
        hasName(f, "timer_init_key") or hasName(f, "timer_init_key_on_stack") or hasName(f, "setup_timer") or hasName(f, "init_timer") or hasName(f, "init_timer_on_stack") or hasName(f, "init_timer_key")
      )
    )
  }
  Expr getTimerArg() { result = this.getArgument(0) }
  Expr getCallbackArg() { result = this.getArgument(1) }
  Function getCallbackFunction() {
    exists(FunctionAccess fa |
      fa = this.getCallbackArg().getUnconverted() and result = fa.getTarget()
    )
    or
    exists(AddressOfExpr addr, FunctionAccess fa |
      addr = this.getCallbackArg().getUnconverted() and
      fa = addr.getOperand().getUnconverted() and result = fa.getTarget()
    )
  }
}

class TimerStartCall extends FunctionCall {
  TimerStartCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        hasName(f, "mod_timer") or hasName(f, "add_timer") or
        hasName(f, "add_timer_on") or hasName(f, "add_timer_local") or
        hasName(f, "add_timer_global") or hasName(f, "mod_timer_pending") or
        hasName(f, "timer_reduce") or hasName(f, "mod_timer_pending")
      )
    )
  }
  Expr getTimerArg() { result = this.getArgument(0) }
  string getStartKind() { result = this.getTarget().getName() }
}

predicate immediateTimerFreeArgument(Function target, int argumentIndex, string freeKind) {
  hasName(target, "kfree") and argumentIndex = 0 and freeKind = "heap"
  or hasName(target, "kfree_sensitive") and argumentIndex = 0 and freeKind = "heap_sensitive"
  or hasName(target, "kfree_const") and argumentIndex = 0 and freeKind = "heap_or_const"
  or hasName(target, "kzfree") and argumentIndex = 0 and freeKind = "heap_zeroed"
  or hasName(target, "kvfree") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc"
  or hasName(target, "kvfree_sensitive") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc_sensitive"
  or hasName(target, "vfree") and argumentIndex = 0 and freeKind = "vmalloc"
  or hasName(target, "vfree_atomic") and argumentIndex = 0 and freeKind = "vmalloc_atomic"
  or hasName(target, "devm_kfree") and argumentIndex = 1 and freeKind = "device_managed_heap"
  or hasName(target, "kmem_cache_free") and argumentIndex = 1 and freeKind = "slab_cache"
  or hasName(target, "mempool_free") and argumentIndex = 0 and freeKind = "mempool"
  or hasName(target, "free_percpu") and argumentIndex = 0 and freeKind = "percpu"
  or hasName(target, "dma_free_coherent") and argumentIndex = 2 and freeKind = "dma_coherent"
  or hasName(target, "dma_free_attrs") and argumentIndex = 2 and freeKind = "dma_attrs"
  or hasName(target, "dma_free_noncoherent") and argumentIndex = 2 and freeKind = "dma_noncoherent"
  or hasName(target, "dmam_free_coherent") and argumentIndex = 2 and freeKind = "device_managed_dma"
  or hasName(target, "dma_pool_free") and argumentIndex = 1 and freeKind = "dma_pool"
  or hasName(target, "pci_free_consistent") and argumentIndex = 2 and freeKind = "pci_consistent"
  or hasName(target, "pci_pool_free") and argumentIndex = 1 and freeKind = "pci_pool"
  or hasName(target, "usb_free_coherent") and argumentIndex = 2 and freeKind = "usb_coherent"
  or hasName(target, "gen_pool_free") and argumentIndex = 1 and freeKind = "generic_pool"
  or hasName(target, "free_pages") and argumentIndex = 0 and freeKind = "pages"
  or hasName(target, "free_pages_exact") and argumentIndex = 0 and freeKind = "pages_exact"
  or hasName(target, "__free_pages") and argumentIndex = 0 and freeKind = "pages_internal"
  or hasName(target, "__free_page") and argumentIndex = 0 and freeKind = "page_internal"
  or hasName(target, "free_page") and argumentIndex = 0 and freeKind = "page"
  or hasName(target, "page_frag_free") and argumentIndex = 0 and freeKind = "page_frag"
  or hasName(target, "free_netdev") and argumentIndex = 0 and freeKind = "netdev"
  or hasName(target, "hci_free_dev") and argumentIndex = 0 and freeKind = "hci_dev"
  or hasName(target, "usb_free_urb") and argumentIndex = 0 and freeKind = "usb_urb"
  or hasName(target, "kfree_skb") and argumentIndex = 0 and freeKind = "skb"
  or hasName(target, "dev_kfree_skb_any") and argumentIndex = 0 and freeKind = "skb"
  or hasName(target, "consume_skb") and argumentIndex = 0 and freeKind = "skb"
  or hasName(target, "kmem_cache_free_bulk") and argumentIndex = 2 and freeKind = "slab_cache_bulk"
  or hasName(target, "kfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_heap"
  or hasName(target, "kvfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_vm"
}

class FreeCall extends FunctionCall {
  FreeCall() {
    exists(int i, string k |
      immediateTimerFreeArgument(this.getTarget(), i, k) and i < this.getNumberOfArguments()
    )
  }
  int getFreedArgumentIndex() { immediateTimerFreeArgument(this.getTarget(), result, _) }
  Expr getFreedExpr() { result = this.getArgument(this.getFreedArgumentIndex()) }
  string getFreeKind() { immediateTimerFreeArgument(this.getTarget(), _, result) }
  string getFreeApi() { result = this.getTarget().getName() }
}

/** Timer cancellation/shutdown context before a free. Used for audit tagging only. */
class TimerBarrierCall extends FunctionCall {
  TimerBarrierCall() {
    hasName(this.getTarget(), "del_timer_sync") or
    hasName(this.getTarget(), "del_singleshot_timer_sync") or
    hasName(this.getTarget(), "timer_delete_sync") or
    hasName(this.getTarget(), "timer_shutdown_sync") or
    hasName(this.getTarget(), "del_timer") or
    hasName(this.getTarget(), "timer_delete") or
    hasName(this.getTarget(), "timer_shutdown") or
    hasName(this.getTarget(), "try_to_del_timer_sync") or
    hasName(this.getTarget(), "timer_delete_sync_try")
  }

  string getApiName() { result = this.getTarget().getName() }
  string getStrength() {
    (
      hasName(this.getTarget(), "del_timer_sync") or
      hasName(this.getTarget(), "del_singleshot_timer_sync") or
      hasName(this.getTarget(), "timer_delete_sync") or
      hasName(this.getTarget(), "timer_shutdown_sync")
    ) and result = "strong"
    or
    (
      hasName(this.getTarget(), "del_timer") or
      hasName(this.getTarget(), "timer_delete") or
      hasName(this.getTarget(), "timer_shutdown") or
      hasName(this.getTarget(), "try_to_del_timer_sync") or
      hasName(this.getTarget(), "timer_delete_sync_try")
    ) and result = "weak"
  }
}

string timerBarrierSummaryForFree(FreeCall free) {
  exists(TimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    result = barrier.getStrength() + "_barrier_before_free:" + barrier.getApiName()
  )
  or
  not exists(TimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "none_in_free_function_before_free"
}

string timerProtectionTagForFree(FreeCall free) {
  exists(TimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(TimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and
  exists(TimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(TimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "no"
}

bindingset[before]
predicate cfgStrictlyAfter(ControlFlowNode before, ControlFlowNode after) {
  before.getControlFlowScope() = after.getControlFlowScope() and
  before.getASuccessor+() = after
}

predicate timerOwnerAndField(Expr timerArg, Expr owner, Field timerField) {
  exists(FieldAccess fa |
    (
      fa = timerArg.getUnconverted()
      or exists(AddressOfExpr addr |
        addr = timerArg.getUnconverted() and fa = addr.getOperand().getUnconverted()
      )
    ) and
    owner = fa.getQualifier().getUnconverted() and timerField = fa.getTarget()
  )
}

string fieldIdentity(Field f) {
  result = f.getFile().getRelativePath() + ":" +
    f.getLocation().getStartLine().toString() + ":" +
    f.getLocation().getStartColumn().toString()
}

bindingset[e]
predicate exprRootAndPath(Expr e, Variable root, string path, int depth) {
  depth = 0 and
  exists(VariableAccess v | v = e.getUnconverted() and root = v.getTarget()) and
  path = ""
  or
  depth = 1 and maxTreeFieldDepth() >= 1 and
  exists(FieldAccess f1, VariableAccess v |
    f1 = e.getUnconverted() and
    v = f1.getQualifier().getUnconverted() and root = v.getTarget() and
    path = fieldIdentity(f1.getTarget())
  )
  or
  depth = 2 and maxTreeFieldDepth() >= 2 and
  exists(FieldAccess f1, FieldAccess f2, VariableAccess v |
    f2 = e.getUnconverted() and f1 = f2.getQualifier().getUnconverted() and
    v = f1.getQualifier().getUnconverted() and root = v.getTarget() and
    path = fieldIdentity(f1.getTarget()) + "/" + fieldIdentity(f2.getTarget())
  )
  or
  depth = 3 and maxTreeFieldDepth() >= 3 and
  exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, VariableAccess v |
    f3 = e.getUnconverted() and f2 = f3.getQualifier().getUnconverted() and
    f1 = f2.getQualifier().getUnconverted() and
    v = f1.getQualifier().getUnconverted() and root = v.getTarget() and
    path = fieldIdentity(f1.getTarget()) + "/" + fieldIdentity(f2.getTarget()) +
      "/" + fieldIdentity(f3.getTarget())
  )
}

predicate variablePointsToType(Variable v, Type targetType) {
  exists(PointerType pt |
    pt = v.getType().getUnspecifiedType() and
    pt.getBaseType().getUnspecifiedType() = targetType.getUnspecifiedType()
  )
}

bindingset[prefix, full]
predicate fieldPathPrefix(string prefix, string full) {
  prefix = "" or prefix = full or full.indexOf(prefix + "/") = 0
}

bindingset[left, right]
string joinFieldPath(string left, string right) {
  left = "" and result = right
  or right = "" and result = left
  or left != "" and right != "" and result = left + "/" + right
}

predicate terminalRealFieldUse(FieldAccess use) {
  not exists(AddressOfExpr addr | addr.getOperand().getUnconverted() = use.getUnconverted()) and
  not exists(FieldAccess outer | outer.getQualifier().getUnconverted() = use.getUnconverted()) and
  (use.isRValue() or use.isModified() or use.isUsedAsLValue())
}

predicate timerTerminalRealFieldUse(FieldAccess use) {
  terminalRealFieldUse(use)
}

predicate teardownLikeFunction(Function f) {
  f.getName().matches("%remove%") or f.getName().matches("%detach%") or
  f.getName().matches("%cleanup%") or f.getName().matches("%destroy%") or
  f.getName().matches("%release%") or f.getName().matches("%shutdown%") or
  f.getName().matches("%unregister%") or f.getName().matches("%deinit%") or
  f.getName().matches("%exit%") or f.getName().matches("free_%") or
  f.getName().matches("%_free")
}

/** Setup and start are both visible in the same function. */
pragma[noinline]
predicate timerDirectLifecycleAnchor(
  TimerStartCall start, TimerSetupCall setup, Function callback,
  Expr lifecycleOwner, Variable lifecycleRoot, Field timerField,
  FunctionCall flowEntry
) {
  exists(Expr setupOwner, Variable setupRoot, string setupPath,
         Expr startOwner, Variable startRoot, string startPath, int sd, int td |
    callback = setup.getCallbackFunction() and
    timerOwnerAndField(setup.getTimerArg(), setupOwner, timerField) and
    exprRootAndPath(setupOwner, setupRoot, setupPath, sd) and setupPath = "" and
    timerOwnerAndField(start.getTimerArg(), startOwner, timerField) and
    exprRootAndPath(startOwner, startRoot, startPath, td) and startPath = "" and
    setup.getEnclosingFunction() = start.getEnclosingFunction() and
    setupRoot = startRoot and cfgStrictlyAfter(setup, start) and
    lifecycleOwner = startOwner and lifecycleRoot = startRoot and
    flowEntry = start
  )
}

/** Setup is in the caller; the concrete start is one call below it. */
pragma[noinline]
predicate timerStartWrapperLifecycleAnchor(
  TimerStartCall start, TimerSetupCall setup, Function callback,
  Expr lifecycleOwner, Variable lifecycleRoot, Field timerField,
  FunctionCall flowEntry
) {
  exists(
    Expr setupOwner, Variable setupRoot, string setupPath, int setupDepth,
    FunctionCall wrapper, int argIndex, Variable argumentRoot, string argumentPath,
    int argumentDepth, Parameter calleeRoot,
    Expr startOwner, Variable startRoot, string startPath, int startDepth
  |
    callback = setup.getCallbackFunction() and
    timerOwnerAndField(setup.getTimerArg(), setupOwner, timerField) and
    exprRootAndPath(setupOwner, setupRoot, setupPath, setupDepth) and setupPath = "" and
    wrapper.getEnclosingFunction() = setup.getEnclosingFunction() and
    cfgStrictlyAfter(setup, wrapper) and
    exprRootAndPath(wrapper.getArgument(argIndex), argumentRoot, argumentPath, argumentDepth) and
    argumentRoot = setupRoot and argumentPath = "" and
    calleeRoot = wrapper.getTarget().getParameter(argIndex) and
    timerOwnerAndField(start.getTimerArg(), startOwner, timerField) and
    start.getEnclosingFunction() = calleeRoot.getFunction() and
    exprRootAndPath(startOwner, startRoot, startPath, startDepth) and
    startRoot = calleeRoot and startPath = "" and
    lifecycleOwner = setupOwner and lifecycleRoot = setupRoot and
    flowEntry = wrapper
  )
}

/** Start is in the caller; setup is performed one call below it. */
pragma[noinline]
predicate timerSetupWrapperLifecycleAnchor(
  TimerStartCall start, TimerSetupCall setup, Function callback,
  Expr lifecycleOwner, Variable lifecycleRoot, Field timerField,
  FunctionCall flowEntry
) {
  exists(
    Expr startOwner, Variable startRoot, string startPath, int startDepth,
    FunctionCall setupWrapper, int argIndex, Variable argumentRoot, string argumentPath,
    int argumentDepth, Parameter calleeRoot,
    Expr setupOwner, Variable setupRoot, string setupPath, int setupDepth
  |
    timerOwnerAndField(start.getTimerArg(), startOwner, timerField) and
    exprRootAndPath(startOwner, startRoot, startPath, startDepth) and startPath = "" and
    setupWrapper.getEnclosingFunction() = start.getEnclosingFunction() and
    cfgStrictlyAfter(setupWrapper, start) and
    exprRootAndPath(setupWrapper.getArgument(argIndex), argumentRoot, argumentPath, argumentDepth) and
    argumentRoot = startRoot and argumentPath = "" and
    calleeRoot = setupWrapper.getTarget().getParameter(argIndex) and
    callback = setup.getCallbackFunction() and
    timerOwnerAndField(setup.getTimerArg(), setupOwner, timerField) and
    setup.getEnclosingFunction() = calleeRoot.getFunction() and
    exprRootAndPath(setupOwner, setupRoot, setupPath, setupDepth) and
    setupRoot = calleeRoot and setupPath = "" and
    lifecycleOwner = startOwner and lifecycleRoot = startRoot and
    flowEntry = start
  )
}

predicate callbackRealUse(
  Function callback, Field timerField, FieldAccess use,
  Variable useRoot, string usePath, int useDepth
) {
  use.getEnclosingFunction() = callback and terminalRealFieldUse(use) and
  exprRootAndPath(use, useRoot, usePath, useDepth) and
  variablePointsToType(useRoot, timerField.getDeclaringType())
}

pragma[noinline]
predicate timerAnyLifecycleAnchor(
  TimerStartCall start, TimerSetupCall setup, Function callback,
  Expr lifecycleOwner, Variable lifecycleRoot, Field timerField,
  FunctionCall flowEntry, int callbackDepth,
  string lifecycleBinding, string setupBinding
) {
  timerDirectLifecycleAnchor(
    start, setup, callback, lifecycleOwner, lifecycleRoot, timerField, flowEntry
  ) and
  callbackDepth = 0 and lifecycleBinding = "direct_setup_start_exact_root" and
  setupBinding = "same_function_setup_before_start"
  or
  timerStartWrapperLifecycleAnchor(
    start, setup, callback, lifecycleOwner, lifecycleRoot, timerField, flowEntry
  ) and
  callbackDepth = 1 and lifecycleBinding = "caller_start_wrapper_exact_root" and
  setupBinding = "caller_setup_to_start_wrapper"
  or
  timerSetupWrapperLifecycleAnchor(
    start, setup, callback, lifecycleOwner, lifecycleRoot, timerField, flowEntry
  ) and
  callbackDepth = 1 and lifecycleBinding = "caller_setup_wrapper_exact_root" and
  setupBinding = "setup_wrapper_to_caller_start"
}

pragma[noinline]
predicate timerCallerDirectFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field timerField,
  FieldAccess use, FreeCall free, int freedFieldDepth
) {
  exists(Variable useRoot, string usePath, int useDepth, string freedPath |
    callbackRealUse(use.getEnclosingFunction(), timerField, use, useRoot, usePath, useDepth) and
    cfgStrictlyAfter(flowEntry, free) and
    exprRootAndPath(free.getFreedExpr(), lifecycleRoot, freedPath, freedFieldDepth) and
    fieldPathPrefix(freedPath, usePath)
  )
}

pragma[noinline]
predicate timerCallerOneHopFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field timerField,
  FieldAccess use, FreeCall free, int freedFieldDepth
) {
  exists(
    Variable useRoot, string usePath, int useDepth,
    FunctionCall helperCall, int argIndex,
    Variable argumentRoot, string argumentPath, int argumentDepth,
    Parameter helperRoot, string helperPath, int helperDepth, string freedPath
  |
    callbackRealUse(use.getEnclosingFunction(), timerField, use, useRoot, usePath, useDepth) and
    cfgStrictlyAfter(flowEntry, helperCall) and not helperCall instanceof FreeCall and
    exprRootAndPath(helperCall.getArgument(argIndex), argumentRoot, argumentPath, argumentDepth) and
    argumentRoot = lifecycleRoot and
    helperRoot = helperCall.getTarget().getParameter(argIndex) and
    free.getEnclosingFunction() = helperRoot.getFunction() and
    exprRootAndPath(free.getFreedExpr(), helperRoot, helperPath, helperDepth) and
    freedPath = joinFieldPath(argumentPath, helperPath) and
    fieldPathPrefix(freedPath, usePath) and
    freedFieldDepth = argumentDepth + helperDepth
  )
}

pragma[noinline]
predicate timerCrossLifecycleDirectFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field timerField,
  FieldAccess use, FreeCall free, int freedFieldDepth
) {
  exists(
    Variable useRoot, string usePath, int useDepth,
    Variable freeRoot, string freedPath
  |
    callbackRealUse(use.getEnclosingFunction(), timerField, use, useRoot, usePath, useDepth) and
    free.getEnclosingFunction() != flowEntry.getEnclosingFunction() and
    teardownLikeFunction(free.getEnclosingFunction()) and
    exprRootAndPath(free.getFreedExpr(), freeRoot, freedPath, freedFieldDepth) and
    freeRoot.getType().getUnspecifiedType() = lifecycleRoot.getType().getUnspecifiedType() and
    variablePointsToType(freeRoot, timerField.getDeclaringType()) and
    fieldPathPrefix(freedPath, usePath)
  )
}

pragma[noinline]
predicate timerCrossLifecycleOneHopFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field timerField,
  FieldAccess use, FreeCall free, int freedFieldDepth
) {
  exists(
    Variable useRoot, string usePath, int useDepth,
    Function teardown, FunctionCall helperCall, int argIndex,
    Variable teardownRoot, string argumentPath, int argumentDepth,
    Parameter helperRoot, string helperPath, int helperDepth, string freedPath
  |
    callbackRealUse(use.getEnclosingFunction(), timerField, use, useRoot, usePath, useDepth) and
    teardown = helperCall.getEnclosingFunction() and
    teardown != flowEntry.getEnclosingFunction() and teardownLikeFunction(teardown) and
    exprRootAndPath(helperCall.getArgument(argIndex), teardownRoot, argumentPath, argumentDepth) and
    teardownRoot.getType().getUnspecifiedType() = lifecycleRoot.getType().getUnspecifiedType() and
    variablePointsToType(teardownRoot, timerField.getDeclaringType()) and
    helperRoot = helperCall.getTarget().getParameter(argIndex) and
    free.getEnclosingFunction() = helperRoot.getFunction() and
    exprRootAndPath(free.getFreedExpr(), helperRoot, helperPath, helperDepth) and
    freedPath = joinFieldPath(argumentPath, helperPath) and
    fieldPathPrefix(freedPath, usePath) and
    freedFieldDepth = argumentDepth + helperDepth
  )
}

pragma[noinline]
predicate timerAnyFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field timerField,
  FieldAccess use, FreeCall free,
  int freeCallDepth, int freedFieldDepth, string flowMode
) {
  timerCallerDirectFreeFinding(
    flowEntry, lifecycleRoot, timerField, use, free, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "direct_cfg_free"
  or
  timerCallerOneHopFreeFinding(
    flowEntry, lifecycleRoot, timerField, use, free, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "caller_one_hop_free"
  or
  timerCrossLifecycleDirectFreeFinding(
    flowEntry, lifecycleRoot, timerField, use, free, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "cross_lifecycle_teardown_root"
  or
  timerCrossLifecycleOneHopFreeFinding(
    flowEntry, lifecycleRoot, timerField, use, free, freedFieldDepth
  ) and
  not timerCrossLifecycleDirectFreeFinding(
    flowEntry, lifecycleRoot, timerField, use, free, freedFieldDepth
  ) and
  freeCallDepth = 1 and flowMode = "cross_lifecycle_one_hop_free"
}


bindingset[depth]
string freedRegionKind(int depth) {
  depth = 0 and result = "whole_timer_owner"
  or depth > 0 and result = "nested_subtree_of_timer_owner"
}

/** Complete materialized Timer result row. */
newtype TTimerConcurrentFreeRow =
  MkTimerConcurrentFreeRow(
    TimerStartCall start, Field timerField, TimerSetupCall setup, Function callback,
    FreeCall free, FunctionCall flowEntry, Expr lifecycleOwner,
    int callbackDepth, string lifecycleBinding, string setupBinding,
    int freeCallDepth, int freedFieldDepth, string flowMode, FieldAccess matchedUse
  ) {
    exists(Variable lifecycleRoot |
      timerAnyLifecycleAnchor(
        start, setup, callback, lifecycleOwner, lifecycleRoot, timerField, flowEntry,
        callbackDepth, lifecycleBinding, setupBinding
      ) and
      matchedUse.getEnclosingFunction() = callback and
      timerAnyFreeFinding(
        flowEntry, lifecycleRoot, timerField, matchedUse, free,
        freeCallDepth, freedFieldDepth, flowMode
      )
    )
  }

class TimerConcurrentFreeRow extends TTimerConcurrentFreeRow {
  TimerStartCall start;
  Field timerField;
  TimerSetupCall setup;
  Function callback;
  FreeCall free;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  int callbackDepth;
  string lifecycleBinding;
  string setupBinding;
  int freeCallDepth;
  int freedFieldDepth;
  string flowMode;
  FieldAccess matchedUse;

  TimerConcurrentFreeRow() {
    this = MkTimerConcurrentFreeRow(
      start, timerField, setup, callback, free, flowEntry, lifecycleOwner,
      callbackDepth, lifecycleBinding, setupBinding,
      freeCallDepth, freedFieldDepth, flowMode, matchedUse
    )
  }

  pragma[noinline] string getLifecycleFile() { result = flowEntry.getFile().getRelativePath() }
  pragma[noinline] int getLifecycleLine() { result = flowEntry.getLocation().getStartLine() }
  pragma[noinline] string getLifecycleFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getLifecycleApi() { result = start.getStartKind() }
  pragma[noinline] string getLifecycleArgument() { result = flowEntry.toString() }
  pragma[noinline] string getLifecycleBinding() { result = lifecycleBinding }
  pragma[noinline] int getCallbackDepth() { result = callbackDepth }
  pragma[noinline] string getSetupBinding() { result = setupBinding }

  pragma[noinline] string getSetupFile() { result = setup.getFile().getRelativePath() }
  pragma[noinline] int getSetupLine() { result = setup.getLocation().getStartLine() }
  pragma[noinline] string getSetupFunction() { result = setup.getEnclosingFunction().getName() }
  pragma[noinline] string getSetupApi() { result = setup.getTarget().getName() }

  pragma[noinline] string getCallbackName() { result = callback.getName() }
  pragma[noinline] string getCallbackFile() { result = callback.getFile().getRelativePath() }
  pragma[noinline] int getCallbackLine() { result = callback.getLocation().getStartLine() }

  pragma[noinline] string getHolderFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getHolderRoot() { result = lifecycleOwner.toString() }
  pragma[noinline] string getHolderType() { result = timerField.getDeclaringType().toString() }
  pragma[noinline] string getTimerFieldName() { result = timerField.getName() }

  pragma[noinline] string getFreeFile() { result = free.getFile().getRelativePath() }
  pragma[noinline] int getFreeLine() { result = free.getLocation().getStartLine() }
  pragma[noinline] string getFreeFunction() { result = free.getEnclosingFunction().getName() }
  pragma[noinline] string getFreeApi() { result = free.getFreeApi() }
  pragma[noinline] string getFreeKind() { result = free.getFreeKind() }
  pragma[noinline] string getFreedExpression() { result = free.getFreedExpr().toString() }
  pragma[noinline] int getFreeCallDepth() { result = freeCallDepth }
  pragma[noinline] string getFreedPathKind() {
    result = freedRegionKind(freedFieldDepth) + ";" + flowMode
  }

  pragma[noinline] string getUseFile() { result = matchedUse.getFile().getRelativePath() }
  pragma[noinline] int getUseLine() { result = matchedUse.getLocation().getStartLine() }
  pragma[noinline] string getUseFunction() { result = matchedUse.getEnclosingFunction().getName() }
  pragma[noinline] string getUseExpression() { result = matchedUse.toString() }

  pragma[noinline] string getBarrierContext() { result = timerBarrierSummaryForFree(free) }
  pragma[noinline] string getProtectionTag() { result = timerProtectionTagForFree(free) }

  string toString() { result = "timer-concurrent-free-row" }
}

