import KernelObjectPathFlow
/**
 * Lightweight Linux hrtimer lifecycle/free versus callback/use model.
 *
 * The query is intentionally bounded: owner paths contain at most three
 * declared fields and setup/start, callback-use, and free wrappers contain
 * at most one direct call edge.  This keeps the analysis relational and avoids
 * whole-program global data flow while preserving the same object-tree
 * semantics as the finalized timer/workqueue queries.
 */

import cpp

predicate hrtimerHasName(Function f, string name) {
  f.hasName(name)
}

int hrtimerMaxTreeFieldDepth() { result = 5 }
int hrtimerMaxWrapperDepth() { result = 3 }

class HrtimerSetupCall extends FunctionCall {
  HrtimerSetupCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        hrtimerHasName(f, "hrtimer_setup") or
        hrtimerHasName(f, "hrtimer_setup_on_stack") or
        hrtimerHasName(f, "hrtimer_init") or
        hrtimerHasName(f, "hrtimer_init_on_stack") or
        hrtimerHasName(f, "hrtimer_init_sleeper") or
        hrtimerHasName(f, "hrtimer_init_sleeper_on_stack")
      ) and
      this.getNumberOfArguments() > 1
    )
  }

  Expr getHrtimerArg() { result = this.getArgument(0) }
  Function getDirectCallbackFunction() {
    (
      hrtimerHasName(this.getTarget(), "hrtimer_setup") or
      hrtimerHasName(this.getTarget(), "hrtimer_setup_on_stack")
    ) and
    exists(FunctionAccess access |
      access = this.getArgument(1).getUnconverted() and
      result = access.getTarget()
    )
    or
    exists(AddressOfExpr address, FunctionAccess access |
      address = this.getArgument(1).getUnconverted() and
      access = address.getOperand().getUnconverted() and
      result = access.getTarget()
    )
  }

  string getSetupKind() {
    (
      hrtimerHasName(this.getTarget(), "hrtimer_setup") or
      hrtimerHasName(this.getTarget(), "hrtimer_setup_on_stack")
    ) and result = "hrtimer_setup_callback"
    or
    (
      hrtimerHasName(this.getTarget(), "hrtimer_init") or
      hrtimerHasName(this.getTarget(), "hrtimer_init_on_stack")
    ) and result = "hrtimer_init_function_assignment"
  }
}

class HrtimerStartCall extends FunctionCall {
  HrtimerStartCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        hrtimerHasName(f, "hrtimer_start") or
        hrtimerHasName(f, "hrtimer_start_range_ns") or
        hrtimerHasName(f, "hrtimer_start_expires") or
        hrtimerHasName(f, "hrtimer_start_expires_range_ns") or
        hrtimerHasName(f, "hrtimer_restart") or
        hrtimerHasName(f, "__hrtimer_start_range_ns")
      ) and
      this.getNumberOfArguments() > 0
    )
  }

  Expr getHrtimerArg() { result = this.getArgument(0) }
  string getStartKind() { result = this.getTarget().getName() }
}

predicate immediateHrtimerFreeArgument(Function target, int argumentIndex, string freeKind) {
  hrtimerHasName(target, "kfree") and argumentIndex = 0 and freeKind = "heap"
  or hrtimerHasName(target, "kfree_sensitive") and argumentIndex = 0 and freeKind = "heap_sensitive"
  or hrtimerHasName(target, "kfree_const") and argumentIndex = 0 and freeKind = "heap_or_const"
  or hrtimerHasName(target, "kzfree") and argumentIndex = 0 and freeKind = "heap_zeroed"
  or hrtimerHasName(target, "kvfree") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc"
  or hrtimerHasName(target, "kvfree_sensitive") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc_sensitive"
  or hrtimerHasName(target, "vfree") and argumentIndex = 0 and freeKind = "vmalloc"
  or hrtimerHasName(target, "vfree_atomic") and argumentIndex = 0 and freeKind = "vmalloc_atomic"
  or hrtimerHasName(target, "devm_kfree") and argumentIndex = 1 and freeKind = "device_managed_heap"
  or hrtimerHasName(target, "kmem_cache_free") and argumentIndex = 1 and freeKind = "slab_cache"
  or hrtimerHasName(target, "mempool_free") and argumentIndex = 0 and freeKind = "mempool"
  or hrtimerHasName(target, "free_percpu") and argumentIndex = 0 and freeKind = "percpu"
  or hrtimerHasName(target, "dma_free_coherent") and argumentIndex = 2 and freeKind = "dma_coherent"
  or hrtimerHasName(target, "dma_free_attrs") and argumentIndex = 2 and freeKind = "dma_attrs"
  or hrtimerHasName(target, "dma_free_noncoherent") and argumentIndex = 2 and freeKind = "dma_noncoherent"
  or hrtimerHasName(target, "dmam_free_coherent") and argumentIndex = 2 and freeKind = "device_managed_dma"
  or hrtimerHasName(target, "dma_pool_free") and argumentIndex = 1 and freeKind = "dma_pool"
  or hrtimerHasName(target, "pci_free_consistent") and argumentIndex = 2 and freeKind = "pci_consistent"
  or hrtimerHasName(target, "pci_pool_free") and argumentIndex = 1 and freeKind = "pci_pool"
  or hrtimerHasName(target, "usb_free_coherent") and argumentIndex = 2 and freeKind = "usb_coherent"
  or hrtimerHasName(target, "gen_pool_free") and argumentIndex = 1 and freeKind = "generic_pool"
  or hrtimerHasName(target, "free_pages") and argumentIndex = 0 and freeKind = "pages"
  or hrtimerHasName(target, "free_pages_exact") and argumentIndex = 0 and freeKind = "pages_exact"
  or hrtimerHasName(target, "__free_pages") and argumentIndex = 0 and freeKind = "pages_internal"
  or hrtimerHasName(target, "__free_page") and argumentIndex = 0 and freeKind = "page_internal"
  or hrtimerHasName(target, "free_page") and argumentIndex = 0 and freeKind = "page"
  or hrtimerHasName(target, "page_frag_free") and argumentIndex = 0 and freeKind = "page_frag"
  or hrtimerHasName(target, "free_netdev") and argumentIndex = 0 and freeKind = "netdev"
  or hrtimerHasName(target, "hci_free_dev") and argumentIndex = 0 and freeKind = "hci_dev"
  or hrtimerHasName(target, "usb_free_urb") and argumentIndex = 0 and freeKind = "usb_urb"
  or hrtimerHasName(target, "kfree_skb") and argumentIndex = 0 and freeKind = "skb"
  or hrtimerHasName(target, "dev_kfree_skb_any") and argumentIndex = 0 and freeKind = "skb"
  or hrtimerHasName(target, "consume_skb") and argumentIndex = 0 and freeKind = "skb"
  or hrtimerHasName(target, "kmem_cache_free_bulk") and argumentIndex = 2 and freeKind = "slab_cache_bulk"
  or hrtimerHasName(target, "kfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_heap"
  or hrtimerHasName(target, "kvfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_vm"
}

class HrtimerFreeCall extends FunctionCall {
  HrtimerFreeCall() {
    exists(int argumentIndex, string freeKind |
      immediateHrtimerFreeArgument(this.getTarget(), argumentIndex, freeKind) and
      argumentIndex < this.getNumberOfArguments()
    )
  }

  int getFreedArgumentIndex() { immediateHrtimerFreeArgument(this.getTarget(), result, _) }
  Expr getFreedExpr() { result = this.getArgument(this.getFreedArgumentIndex()) }
  string getFreeKind() { immediateHrtimerFreeArgument(this.getTarget(), _, result) }
  string getFreeApi() { result = this.getTarget().getName() }
}

bindingset[before]
predicate hrtimerCfgStrictlyAfter(ControlFlowNode before, ControlFlowNode after) {
  before.getControlFlowScope() = after.getControlFlowScope() and
  before.getASuccessor+() = after
}

predicate hrtimerOwnerAndField(Expr hrtimerArg, Expr owner, Field hrtimerField) {
  exists(FieldAccess access |
    (
      access = hrtimerArg.getUnconverted()
      or exists(AddressOfExpr address |
        address = hrtimerArg.getUnconverted() and
        access = address.getOperand().getUnconverted()
      )
    ) and
    owner = access.getQualifier().getUnconverted() and
    hrtimerField = access.getTarget() and
    hrtimerField.getType().getUnspecifiedType().hasName("hrtimer")
  )
}

string hrtimerFieldIdentity(Field field) {
  result = field.getFile().getRelativePath() + ":" +
    field.getLocation().getStartLine().toString() + ":" +
    field.getLocation().getStartColumn().toString()
}

Expr hrtimerStripAddressExpr(Expr expression) {
  not expression.getUnconverted() instanceof AddressOfExpr and
  result = expression.getUnconverted()
  or
  exists(AddressOfExpr address |
    address = expression.getUnconverted() and
    result = address.getOperand().getUnconverted()
  )
}

bindingset[expression]
predicate hrtimerExprRootAndPath(
  Expr expression, Variable root,
  string identityPath, string displayPath, int depth
) {
  depth = 0 and
  exists(VariableAccess access |
    access = hrtimerStripAddressExpr(expression) and root = access.getTarget()
  ) and
  identityPath = "" and displayPath = ""
  or
  depth = 1 and hrtimerMaxTreeFieldDepth() >= 1 and
  exists(FieldAccess f1, VariableAccess access |
    f1 = hrtimerStripAddressExpr(expression) and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = hrtimerFieldIdentity(f1.getTarget()) and
    displayPath = f1.getTarget().getName()
  )
  or
  depth = 2 and hrtimerMaxTreeFieldDepth() >= 2 and
  exists(FieldAccess f1, FieldAccess f2, VariableAccess access |
    f2 = hrtimerStripAddressExpr(expression) and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = hrtimerFieldIdentity(f1.getTarget()) + "/" + hrtimerFieldIdentity(f2.getTarget()) and
    displayPath = f1.getTarget().getName() + "." + f2.getTarget().getName()
  )
  or
  depth = 3 and hrtimerMaxTreeFieldDepth() >= 3 and
  exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, VariableAccess access |
    f3 = hrtimerStripAddressExpr(expression) and
    f2 = f3.getQualifier().getUnconverted() and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = hrtimerFieldIdentity(f1.getTarget()) + "/" +
      hrtimerFieldIdentity(f2.getTarget()) + "/" + hrtimerFieldIdentity(f3.getTarget()) and
    displayPath = f1.getTarget().getName() + "." +
      f2.getTarget().getName() + "." + f3.getTarget().getName()
  )
}

predicate hrtimerVariablePointsToType(Variable variable, Type targetType) {
  exists(PointerType pointer |
    pointer = variable.getType().getUnspecifiedType() and
    pointer.getBaseType().getUnspecifiedType() = targetType.getUnspecifiedType()
  )
}

bindingset[leftIdentity, rightIdentity]
string hrtimerJoinIdentityPath(string leftIdentity, string rightIdentity) {
  leftIdentity = "" and result = rightIdentity
  or rightIdentity = "" and result = leftIdentity
  or leftIdentity != "" and rightIdentity != "" and
    result = leftIdentity + "/" + rightIdentity
}

bindingset[leftDisplay, rightDisplay]
string hrtimerJoinDisplayPath(string leftDisplay, string rightDisplay) {
  leftDisplay = "" and result = rightDisplay
  or rightDisplay = "" and result = leftDisplay
  or leftDisplay != "" and rightDisplay != "" and
    result = leftDisplay + "." + rightDisplay
}

bindingset[prefix, full]
predicate hrtimerPathPrefix(string prefix, string full) {
  prefix = "" or prefix = full or full.indexOf(prefix + "/") = 0
}

predicate hrtimerTerminalRealFieldUse(FieldAccess use) {
  not exists(AddressOfExpr address |
    address.getOperand().getUnconverted() = use.getUnconverted()
  ) and
  not exists(FieldAccess outer |
    outer.getQualifier().getUnconverted() = use.getUnconverted()
  ) and
  (use.isRValue() or use.isModified() or use.isUsedAsLValue())
}

/** The declared hrtimer field and registered hrtimer callback are exact. */
predicate hrtimerSetupMatchesField(
  HrtimerSetupCall setup, Field hrtimerField, Function callback
) {
  exists(Expr setupOwner |
    hrtimerOwnerAndField(setup.getHrtimerArg(), setupOwner, hrtimerField) and
    (
      callback = setup.getDirectCallbackFunction()
      or
      exists(
        AssignExpr assignment, FieldAccess functionMember,
        Expr assignmentOwner, Variable setupRoot, Variable assignmentRoot,
        string setupIdentity, string setupDisplay, int setupDepth,
        string assignmentIdentity, string assignmentDisplay, int assignmentDepth,
        FunctionAccess callbackAccess
      |
        (
          hrtimerHasName(setup.getTarget(), "hrtimer_init") or
          hrtimerHasName(setup.getTarget(), "hrtimer_init_on_stack")
        ) and
        assignment.getEnclosingFunction() = setup.getEnclosingFunction() and
        assignment.getLocation().getStartLine() >= setup.getLocation().getStartLine() and
        functionMember = assignment.getLValue().getUnconverted() and
        functionMember.getTarget().getName() = "function" and
        hrtimerOwnerAndField(
          functionMember.getQualifier(), assignmentOwner, hrtimerField
        ) and
        hrtimerExprRootAndPath(
          setupOwner, setupRoot, setupIdentity, setupDisplay, setupDepth
        ) and setupIdentity = "" and
        hrtimerExprRootAndPath(
          assignmentOwner, assignmentRoot,
          assignmentIdentity, assignmentDisplay, assignmentDepth
        ) and assignmentIdentity = "" and setupRoot = assignmentRoot and
        callbackAccess = assignment.getRValue().getUnconverted() and
        callback = callbackAccess.getTarget()
      )
    )
  )
}

/** Direct hrtimer_start*(&owner->hrtimer). */
pragma[noinline]
predicate hrtimerDirectLifecycleAnchor(
  HrtimerSetupCall setup, HrtimerStartCall start, Field hrtimerField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(string identityPath, string displayPath, int depth |
    hrtimerSetupMatchesField(setup, hrtimerField, callback) and
    hrtimerOwnerAndField(start.getHrtimerArg(), lifecycleOwner, hrtimerField) and
    hrtimerExprRootAndPath(
      lifecycleOwner, lifecycleRoot, identityPath, displayPath, depth
    ) and identityPath = "" and
    hrtimerVariablePointsToType(lifecycleRoot, hrtimerField.getDeclaringType()) and
    flowEntry = start
  )
}

/** Caller passes owner to a one-hop wrapper that performs hrtimer_start*. */
pragma[noinline]
predicate hrtimerOwnerStartWrapperLifecycleAnchor(
  HrtimerSetupCall setup, HrtimerStartCall start, Field hrtimerField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(
    Expr startOwner, Variable startRoot,
    string startIdentity, string startDisplay, int startDepth,
    FunctionCall wrapper, int argumentIndex,
    Variable callerRoot, string argumentIdentity, string argumentDisplay,
    int argumentDepth, Parameter calleeRoot
  |
    hrtimerMaxWrapperDepth() >= 3 and
    hrtimerSetupMatchesField(setup, hrtimerField, callback) and
    hrtimerOwnerAndField(start.getHrtimerArg(), startOwner, hrtimerField) and
    hrtimerExprRootAndPath(
      startOwner, startRoot, startIdentity, startDisplay, startDepth
    ) and startIdentity = "" and
    calleeRoot = startRoot and
    wrapper.getTarget() = start.getEnclosingFunction() and
    calleeRoot = wrapper.getTarget().getParameter(argumentIndex) and
    hrtimerExprRootAndPath(
      wrapper.getArgument(argumentIndex), callerRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and argumentIdentity = "" and
    hrtimerVariablePointsToType(callerRoot, hrtimerField.getDeclaringType()) and
    lifecycleOwner = wrapper.getArgument(argumentIndex).getUnconverted() and
    lifecycleRoot = callerRoot and flowEntry = wrapper
  )
}

/** Caller passes &owner->hrtimer to a one-hop wrapper taking struct hrtimer *. */
pragma[noinline]
predicate hrtimerFieldStartWrapperLifecycleAnchor(
  HrtimerSetupCall setup, HrtimerStartCall start, Field hrtimerField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(
    FunctionCall wrapper, int argumentIndex, Parameter calleeHrtimer,
    VariableAccess startParameter,
    string ownerIdentity, string ownerDisplay, int ownerDepth
  |
    hrtimerMaxWrapperDepth() >= 3 and
    hrtimerSetupMatchesField(setup, hrtimerField, callback) and
    wrapper.getTarget() = start.getEnclosingFunction() and
    calleeHrtimer = wrapper.getTarget().getParameter(argumentIndex) and
    startParameter = start.getHrtimerArg().getUnconverted() and
    startParameter.getTarget() = calleeHrtimer and
    hrtimerOwnerAndField(wrapper.getArgument(argumentIndex), lifecycleOwner, hrtimerField) and
    hrtimerExprRootAndPath(
      lifecycleOwner, lifecycleRoot, ownerIdentity, ownerDisplay, ownerDepth
    ) and ownerIdentity = "" and
    hrtimerVariablePointsToType(lifecycleRoot, hrtimerField.getDeclaringType()) and
    flowEntry = wrapper
  )
}

pragma[noinline]
predicate hrtimerAnyLifecycleAnchor(
  HrtimerSetupCall setup, HrtimerStartCall start, Field hrtimerField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry, int startWrapperDepth, string lifecycleBinding
) {
  hrtimerDirectLifecycleAnchor(
    setup, start, hrtimerField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and startWrapperDepth = 0 and lifecycleBinding = "direct_start_exact_owner"
  or
  hrtimerOwnerStartWrapperLifecycleAnchor(
    setup, start, hrtimerField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and startWrapperDepth = 1 and lifecycleBinding = "owner_start_wrapper_exact_parameter"
  or
  hrtimerFieldStartWrapperLifecycleAnchor(
    setup, start, hrtimerField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and startWrapperDepth = 1 and lifecycleBinding = "hrtimer_field_start_wrapper_exact_parameter"
}

/** container_of with the exact embedded hrtimer Field. */
predicate hrtimerModernCallbackOwner(
  Function callback, Field hrtimerField, Variable callbackOwner
) {
  exists(MacroInvocation recover, LocalVariable local, Initializer initializer |
    recover.getEnclosingFunction() = callback and
    recover.getUnexpandedArgument(2) = hrtimerField.getName() and
    local = callbackOwner and local.getFunction() = callback and
    initializer = local.getInitializer() and (initializer.getExpr() = recover.getExpr() or kernelLocalValueFlow(recover.getExpr(), local.getAnAccess())) and
    hrtimerVariablePointsToType(local, hrtimerField.getDeclaringType())
  )
}

predicate hrtimerCallbackOwnerSeed(
  HrtimerSetupCall setup, Function callback, Field hrtimerField,
  Variable callbackOwner, string recoveryKind
) {
  hrtimerSetupMatchesField(setup, hrtimerField, callback) and
  hrtimerModernCallbackOwner(callback, hrtimerField, callbackOwner) and
  recoveryKind = "container_of_exact_hrtimer_field"
}

Function hrtimerVariableFunction(Variable variable) {
  exists(Parameter parameter |
    variable = parameter and result = parameter.getFunction()
  )
  or
  exists(LocalVariable local |
    variable = local and result = local.getFunction()
  )
}

pragma[noinline]
predicate hrtimerDirectCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(int useDepth |
    use.getEnclosingFunction() = hrtimerVariableFunction(callbackOwner) and
    hrtimerTerminalRealFieldUse(use) and
    hrtimerExprRootAndPath(
      use, callbackOwner, useIdentityPath, useDisplayPath, useDepth
    )
  )
}

pragma[noinline]
predicate hrtimerOneHopCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    hrtimerMaxWrapperDepth() >= 3 and
    helperCall.getEnclosingFunction() = hrtimerVariableFunction(callbackOwner) and
    hrtimerExprRootAndPath(
      helperCall.getArgument(argumentIndex), callbackOwner,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    use.getEnclosingFunction() = helperRoot.getFunction() and
    hrtimerTerminalRealFieldUse(use) and
    hrtimerExprRootAndPath(
      use, helperRoot, helperIdentity, helperDisplay, helperDepth
    ) and
    useIdentityPath = hrtimerJoinIdentityPath(argumentIdentity, helperIdentity) and
    useDisplayPath = hrtimerJoinDisplayPath(argumentDisplay, helperDisplay)
  )
}

pragma[noinline]
predicate hrtimerTwoHopCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(FunctionCall firstCall, FunctionCall secondCall,
    int firstIndex, int secondIndex,
    string firstIdentity, string firstDisplay, string secondIdentity, string secondDisplay,
    int firstDepth, int secondDepth, int useDepth, Parameter firstRoot, Parameter secondRoot |
    hrtimerMaxWrapperDepth() >= 3 and
    firstCall.getEnclosingFunction() = hrtimerVariableFunction(callbackOwner) and
    hrtimerExprRootAndPath(firstCall.getArgument(firstIndex), callbackOwner,
      firstIdentity, firstDisplay, firstDepth) and
    firstRoot = firstCall.getTarget().getParameter(firstIndex) and
    secondCall.getEnclosingFunction() = firstRoot.getFunction() and
    hrtimerExprRootAndPath(secondCall.getArgument(secondIndex), firstRoot,
      secondIdentity, secondDisplay, secondDepth) and
    secondRoot = secondCall.getTarget().getParameter(secondIndex) and
    use.getEnclosingFunction() = secondRoot.getFunction() and
    hrtimerTerminalRealFieldUse(use) and
    hrtimerExprRootAndPath(use, secondRoot, useIdentityPath, useDisplayPath, useDepth)
  )
}
predicate hrtimerAnyCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath, int callbackCallDepth
) {
  hrtimerDirectCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 0
  or
  hrtimerOneHopCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 1
  or
  hrtimerTwoHopCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 2
}

/**
 * Materialize the rare exact setup/field/callback/lifecycle binding before
 * scanning callback bodies.  On large kernel databases this prevents the
 * optimizer from expanding every FieldAccess before the hrtimer seed is known.
 */
newtype THrtimerBoundLifecycle =
  MkHrtimerBoundLifecycle(
    HrtimerSetupCall setup, HrtimerStartCall start, Field hrtimerField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner, Variable lifecycleRoot,
    int startWrapperDepth, string lifecycleBinding
  ) {
    hrtimerAnyLifecycleAnchor(
      setup, start, hrtimerField, callback, lifecycleOwner, lifecycleRoot,
      flowEntry, startWrapperDepth, lifecycleBinding
    ) and
    hrtimerCallbackOwnerSeed(
      setup, callback, hrtimerField, callbackOwner, callbackRecovery
    )
  }

class HrtimerBoundLifecycle extends THrtimerBoundLifecycle {
  HrtimerSetupCall setup;
  HrtimerStartCall start;
  Field hrtimerField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  Variable lifecycleRoot;
  int startWrapperDepth;
  string lifecycleBinding;

  HrtimerBoundLifecycle() {
    this = MkHrtimerBoundLifecycle(
      setup, start, hrtimerField, callback, callbackOwner, callbackRecovery,
      flowEntry, lifecycleOwner, lifecycleRoot,
      startWrapperDepth, lifecycleBinding
    )
  }

  HrtimerSetupCall getSetup() { result = setup }
  HrtimerStartCall getStart() { result = start }
  Field getHrtimerField() { result = hrtimerField }
  Function getCallback() { result = callback }
  Variable getCallbackOwner() { result = callbackOwner }
  string getCallbackRecovery() { result = callbackRecovery }
  FunctionCall getFlowEntry() { result = flowEntry }
  Expr getLifecycleOwner() { result = lifecycleOwner }
  Variable getLifecycleRoot() { result = lifecycleRoot }
  int getStartWrapperDepth() { result = startWrapperDepth }
  string getLifecycleBinding() { result = lifecycleBinding }
  string toString() { result = "hrtimer-bound-lifecycle" }
}

/** Materialize only concrete terminal callback accesses for the bound seed. */
newtype THrtimerBoundUse =
  MkHrtimerBoundUse(
    HrtimerBoundLifecycle lifecycle, FieldAccess use,
    string useIdentityPath, string useDisplayPath, int callbackCallDepth
  ) {
    hrtimerAnyCallbackRealUse(
      lifecycle.getCallbackOwner(), use,
      useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

class HrtimerBoundUse extends THrtimerBoundUse {
  HrtimerBoundLifecycle lifecycle;
  FieldAccess use;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;

  HrtimerBoundUse() {
    this = MkHrtimerBoundUse(
      lifecycle, use, useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

  HrtimerBoundLifecycle getLifecycle() { result = lifecycle }
  FieldAccess getUse() { result = use }
  string getUseIdentityPath() { result = useIdentityPath }
  string getUseDisplayPath() { result = useDisplayPath }
  int getCallbackCallDepth() { result = callbackCallDepth }
  string toString() { result = "hrtimer-bound-use" }
}

predicate hrtimerTeardownLikeFunction(Function function) {
  function.getName().matches("%remove%") or function.getName().matches("%detach%") or
  function.getName().matches("%cleanup%") or function.getName().matches("%destroy%") or
  function.getName().matches("%release%") or function.getName().matches("%shutdown%") or
  function.getName().matches("%unregister%") or function.getName().matches("%deinit%") or
  function.getName().matches("%exit%") or function.getName().matches("%stop%") or
  function.getName().matches("%close%") or function.getName().matches("free_%") or
  function.getName().matches("%_free")
}

/**
 * Sparse, use-independent teardown/free seeds.
 *
 * Keeping these tuples independent of HrtimerBoundUse is important: otherwise
 * the evaluator may repeatedly join every callback FieldAccess with every
 * free call before it can apply the file, owner-type, and path restrictions.
 */
newtype THrtimerCrossDirectFreeSeed =
  MkHrtimerCrossDirectFreeSeed(
    Type ownerType, Function teardown, HrtimerFreeCall free,
    string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
  ) {
    teardown = free.getEnclosingFunction() and
    hrtimerTeardownLikeFunction(teardown) and
    exists(Variable freeRoot, PointerType ownerPointer |
      hrtimerExprRootAndPath(
        free.getFreedExpr(), freeRoot,
        freeIdentityPath, freeDisplayPath, freedFieldDepth
      ) and
      ownerPointer = freeRoot.getType().getUnspecifiedType() and
      ownerType = ownerPointer.getBaseType().getUnspecifiedType()
    )
  }

class HrtimerCrossDirectFreeSeed extends THrtimerCrossDirectFreeSeed {
  Type ownerType;
  Function teardown;
  HrtimerFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freedFieldDepth;

  HrtimerCrossDirectFreeSeed() {
    this = MkHrtimerCrossDirectFreeSeed(
      ownerType, teardown, free,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

  Type getOwnerType() { result = ownerType }
  Function getTeardown() { result = teardown }
  HrtimerFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string toString() { result = "hrtimer-cross-direct-free-seed" }
}

newtype THrtimerCrossOneHopFreeSeed =
  MkHrtimerCrossOneHopFreeSeed(
    Type ownerType, Function teardown, HrtimerFreeCall free,
    string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
  ) {
    exists(
      FunctionCall helperCall, int argumentIndex,
      Variable teardownRoot, PointerType ownerPointer,
      string argumentIdentity, string argumentDisplay, int argumentDepth,
      Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
    |
      hrtimerMaxWrapperDepth() >= 3 and
      teardown = helperCall.getEnclosingFunction() and
      hrtimerTeardownLikeFunction(teardown) and
      not helperCall instanceof HrtimerFreeCall and
      hrtimerExprRootAndPath(
        helperCall.getArgument(argumentIndex), teardownRoot,
        argumentIdentity, argumentDisplay, argumentDepth
      ) and
      ownerPointer = teardownRoot.getType().getUnspecifiedType() and
      ownerType = ownerPointer.getBaseType().getUnspecifiedType() and
      helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
      free.getEnclosingFunction() = helperRoot.getFunction() and
      hrtimerExprRootAndPath(
        free.getFreedExpr(), helperRoot,
        helperIdentity, helperDisplay, helperDepth
      ) and
      freeIdentityPath = hrtimerJoinIdentityPath(argumentIdentity, helperIdentity) and
      freeDisplayPath = hrtimerJoinDisplayPath(argumentDisplay, helperDisplay) and
      freedFieldDepth = argumentDepth + helperDepth
    )
  }

class HrtimerCrossOneHopFreeSeed extends THrtimerCrossOneHopFreeSeed {
  Type ownerType;
  Function teardown;
  HrtimerFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freedFieldDepth;

  HrtimerCrossOneHopFreeSeed() {
    this = MkHrtimerCrossOneHopFreeSeed(
      ownerType, teardown, free,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

  Type getOwnerType() { result = ownerType }
  Function getTeardown() { result = teardown }
  HrtimerFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string toString() { result = "hrtimer-cross-one-hop-free-seed" }
}

pragma[noinline]
predicate hrtimerCallerDirectFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  HrtimerBoundUse boundUse, HrtimerFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  free.getEnclosingFunction() = flowEntry.getEnclosingFunction() and
  free.getLocation().getStartLine() > flowEntry.getLocation().getStartLine() and
  hrtimerExprRootAndPath(
    free.getFreedExpr(), lifecycleRoot,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and
  hrtimerPathPrefix(freeIdentityPath, boundUse.getUseIdentityPath())
}

pragma[noinline]
predicate hrtimerCallerOneHopFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  HrtimerBoundUse boundUse, HrtimerFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    hrtimerMaxWrapperDepth() >= 3 and
    helperCall.getEnclosingFunction() = flowEntry.getEnclosingFunction() and
    helperCall.getLocation().getStartLine() > flowEntry.getLocation().getStartLine() and
    not helperCall instanceof HrtimerFreeCall and
    hrtimerExprRootAndPath(
      helperCall.getArgument(argumentIndex), lifecycleRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    free.getEnclosingFunction() = helperRoot.getFunction() and
    hrtimerExprRootAndPath(
      free.getFreedExpr(), helperRoot,
      helperIdentity, helperDisplay, helperDepth
    ) and
    freeIdentityPath = hrtimerJoinIdentityPath(argumentIdentity, helperIdentity) and
    freeDisplayPath = hrtimerJoinDisplayPath(argumentDisplay, helperDisplay) and
    freedFieldDepth = argumentDepth + helperDepth and
    hrtimerPathPrefix(freeIdentityPath, boundUse.getUseIdentityPath())
  )
}

pragma[noinline]
predicate hrtimerCrossLifecycleDirectFreeFinding(
  FunctionCall flowEntry, Field hrtimerField, Function callback,
  HrtimerBoundUse boundUse, HrtimerFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(HrtimerCrossDirectFreeSeed seed |
    seed.getTeardown() != flowEntry.getEnclosingFunction() and
    seed.getTeardown() != callback and
    seed.getOwnerType() = hrtimerField.getDeclaringType().getUnspecifiedType() and
    free = seed.getFree() and
    freeIdentityPath = seed.getFreeIdentityPath() and
    freeDisplayPath = seed.getFreeDisplayPath() and
    freedFieldDepth = seed.getFreedFieldDepth() and
    hrtimerPathPrefix(seed.getFreeIdentityPath(), boundUse.getUseIdentityPath())
  )
}

pragma[noinline]
predicate hrtimerCrossLifecycleOneHopFreeFinding(
  FunctionCall flowEntry, Field hrtimerField, Function callback,
  HrtimerBoundUse boundUse, HrtimerFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(HrtimerCrossOneHopFreeSeed seed |
    seed.getTeardown() != flowEntry.getEnclosingFunction() and
    seed.getTeardown() != callback and
    seed.getOwnerType() = hrtimerField.getDeclaringType().getUnspecifiedType() and
    free = seed.getFree() and
    freeIdentityPath = seed.getFreeIdentityPath() and
    freeDisplayPath = seed.getFreeDisplayPath() and
    freedFieldDepth = seed.getFreedFieldDepth() and
    hrtimerPathPrefix(seed.getFreeIdentityPath(), boundUse.getUseIdentityPath())
  )
}

pragma[noinline]
predicate hrtimerAnyFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field hrtimerField, Function callback,
  HrtimerBoundUse boundUse, HrtimerFreeCall free,
  string freeIdentityPath, string freeDisplayPath,
  int freeCallDepth, int freedFieldDepth, string flowMode
) {
  hrtimerCallerDirectFreeFinding(
    flowEntry, lifecycleRoot, boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "direct_cfg_free"
  or
  hrtimerCallerOneHopFreeFinding(
    flowEntry, lifecycleRoot, boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "caller_one_hop_free"
  or
  hrtimerCrossLifecycleDirectFreeFinding(
    flowEntry, hrtimerField, callback,
    boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "cross_lifecycle_teardown_root"
  or
  hrtimerCrossLifecycleOneHopFreeFinding(
    flowEntry, hrtimerField, callback,
    boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "cross_lifecycle_one_hop_free"
}

bindingset[depth]
string hrtimerFreedRegionKind(int depth) {
  depth = 0 and result = "whole_hrtimer_owner"
  or depth > 0 and result = "nested_subtree_of_hrtimer_owner"
}

class HrtimerBarrierCall extends FunctionCall {
  HrtimerBarrierCall() {
    hrtimerHasName(this.getTarget(), "hrtimer_cancel") or
    hrtimerHasName(this.getTarget(), "hrtimer_cancel_wait_running") or
    hrtimerHasName(this.getTarget(), "hrtimer_try_to_cancel")
  }

  string getApiName() { result = this.getTarget().getName() }
  string getStrength() {
    (
      hrtimerHasName(this.getTarget(), "hrtimer_cancel") or
      hrtimerHasName(this.getTarget(), "hrtimer_cancel_wait_running")
    ) and result = "strong"
    or
    hrtimerHasName(this.getTarget(), "hrtimer_try_to_cancel") and result = "weak"
  }
}

string hrtimerBarrierSummaryForFree(HrtimerFreeCall free) {
  exists(HrtimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    result = barrier.getStrength() + "_barrier_before_free:" + barrier.getApiName()
  )
  or
  not exists(HrtimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "none_in_free_function_before_free"
}

string hrtimerProtectionTagForFree(HrtimerFreeCall free) {
  exists(HrtimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(HrtimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and
  exists(HrtimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(HrtimerBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "no"
}

newtype THrtimerConcurrentFreeRow =
  MkHrtimerConcurrentFreeRow(
    HrtimerSetupCall setup, HrtimerStartCall start, Field hrtimerField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner,
    int startWrapperDepth, string lifecycleBinding,
    FieldAccess matchedUse, string useIdentityPath, string useDisplayPath,
    int callbackCallDepth,
    HrtimerFreeCall free, string freeDisplayPath,
    int freeCallDepth, int freedFieldDepth, string flowMode
  ) {
    exists(
      HrtimerBoundUse boundUse, HrtimerBoundLifecycle lifecycle,
      string freeIdentityPath
    |
      boundUse.getLifecycle() = lifecycle and
      setup = lifecycle.getSetup() and
      start = lifecycle.getStart() and
      hrtimerField = lifecycle.getHrtimerField() and
      callback = lifecycle.getCallback() and
      callbackOwner = lifecycle.getCallbackOwner() and
      callbackRecovery = lifecycle.getCallbackRecovery() and
      flowEntry = lifecycle.getFlowEntry() and
      lifecycleOwner = lifecycle.getLifecycleOwner() and
      startWrapperDepth = lifecycle.getStartWrapperDepth() and
      lifecycleBinding = lifecycle.getLifecycleBinding() and
      matchedUse = boundUse.getUse() and
      useIdentityPath = boundUse.getUseIdentityPath() and
      useDisplayPath = boundUse.getUseDisplayPath() and
      callbackCallDepth = boundUse.getCallbackCallDepth() and
      hrtimerAnyFreeFinding(
        flowEntry, lifecycle.getLifecycleRoot(), hrtimerField, callback,
        boundUse, free,
        freeIdentityPath, freeDisplayPath,
        freeCallDepth, freedFieldDepth, flowMode
      )
    )
  }

class HrtimerConcurrentFreeRow extends THrtimerConcurrentFreeRow {
  HrtimerSetupCall setup;
  HrtimerStartCall start;
  Field hrtimerField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  int startWrapperDepth;
  string lifecycleBinding;
  FieldAccess matchedUse;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;
  HrtimerFreeCall free;
  string freeDisplayPath;
  int freeCallDepth;
  int freedFieldDepth;
  string flowMode;

  HrtimerConcurrentFreeRow() {
    this = MkHrtimerConcurrentFreeRow(
      setup, start, hrtimerField,
      callback, callbackOwner, callbackRecovery,
      flowEntry, lifecycleOwner,
      startWrapperDepth, lifecycleBinding,
      matchedUse, useIdentityPath, useDisplayPath, callbackCallDepth,
      free, freeDisplayPath, freeCallDepth, freedFieldDepth, flowMode
    )
  }

  pragma[noinline] string getLifecycleFile() { result = flowEntry.getFile().getRelativePath() }
  pragma[noinline] int getLifecycleLine() { result = flowEntry.getLocation().getStartLine() }
  pragma[noinline] string getLifecycleFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getLifecycleApi() { result = start.getStartKind() }
  pragma[noinline] string getLifecycleArgument() { result = flowEntry.toString() }
  pragma[noinline] string getLifecycleBinding() { result = lifecycleBinding }
  pragma[noinline] int getStartWrapperDepth() { result = startWrapperDepth }

  pragma[noinline] string getSetupFile() { result = setup.getFile().getRelativePath() }
  pragma[noinline] int getSetupLine() { result = setup.getLocation().getStartLine() }
  pragma[noinline] string getSetupFunction() { result = setup.getEnclosingFunction().getName() }
  pragma[noinline] string getSetupApi() { result = setup.getTarget().getName() }
  pragma[noinline] string getSetupBinding() { result = hrtimerField.getName() }

  pragma[noinline] string getCallbackName() { result = callback.getName() }
  pragma[noinline] string getCallbackFile() { result = callback.getFile().getRelativePath() }
  pragma[noinline] int getCallbackLine() { result = callback.getLocation().getStartLine() }
  pragma[noinline] string getCallbackRecovery() { result = callbackRecovery }
  pragma[noinline] string getCallbackKind() { result = setup.getSetupKind() }
  pragma[noinline] int getCallbackCallDepth() { result = callbackCallDepth }

  pragma[noinline] string getHolderFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getHolderRoot() { result = lifecycleOwner.toString() }
  pragma[noinline] string getHolderType() { result = hrtimerField.getDeclaringType().toString() }
  pragma[noinline] string getHrtimerFieldName() { result = hrtimerField.getName() }

  pragma[noinline] string getFreeFile() { result = free.getFile().getRelativePath() }
  pragma[noinline] int getFreeLine() { result = free.getLocation().getStartLine() }
  pragma[noinline] string getFreeFunction() { result = free.getEnclosingFunction().getName() }
  pragma[noinline] string getFreeApi() { result = free.getFreeApi() }
  pragma[noinline] string getFreeKind() { result = free.getFreeKind() }
  pragma[noinline] string getFreedExpression() { result = free.getFreedExpr().toString() }
  pragma[noinline] string getFreedObjectPath() {
    freeDisplayPath = "" and result = "<owner>"
    or freeDisplayPath != "" and result = freeDisplayPath
  }
  pragma[noinline] int getFreeCallDepth() { result = freeCallDepth }
  pragma[noinline] string getFreedPathKind() {
    result = hrtimerFreedRegionKind(freedFieldDepth) + ";" + flowMode
  }

  pragma[noinline] string getUseFile() { result = matchedUse.getFile().getRelativePath() }
  pragma[noinline] int getUseLine() { result = matchedUse.getLocation().getStartLine() }
  pragma[noinline] string getUseFunction() { result = matchedUse.getEnclosingFunction().getName() }
  pragma[noinline] string getUseExpression() { result = matchedUse.toString() }
  pragma[noinline] string getUsedObjectPath() {
    useDisplayPath = "" and result = "<owner>"
    or useDisplayPath != "" and result = useDisplayPath
  }
  pragma[noinline] string getBarrierContext() { result = hrtimerBarrierSummaryForFree(free) }
  pragma[noinline] string getProtectionTag() { result = hrtimerProtectionTagForFree(free) }

  string toString() { result = "hrtimer-concurrent-free-row" }
}
