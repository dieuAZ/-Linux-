/**
 * Lightweight Linux rcu lifecycle/free versus callback/use model.
 *
 * The query is intentionally bounded: owner paths contain at most three
 * declared fields and setup/defer, callback-use, and free wrappers contain
 * at most one direct call edge.  This keeps the analysis relational and avoids
 * whole-program global data flow while preserving the same object-tree
 * semantics as the finalized timer/workqueue queries.
 */

import KernelObjectPathFlow
import cpp

predicate rcuHasName(Function f, string name) {
  f.hasName(name)
}

int rcuMaxTreeFieldDepth() { result = 5 }
int rcuMaxWrapperDepth() { result = 3 }

predicate rcuCallbackApi(
  Function target, int headArgument, int callbackArgument, string domain
) {
  (
    rcuHasName(target, "call_rcu") or
    rcuHasName(target, "call_rcu_hurry") or
    rcuHasName(target, "call_rcu_bh") or
    rcuHasName(target, "call_rcu_sched")
  ) and headArgument = 0 and callbackArgument = 1 and domain = "rcu"
  or
  rcuHasName(target, "call_rcu_tasks") and
  headArgument = 0 and callbackArgument = 1 and domain = "rcu_tasks"
  or
  rcuHasName(target, "call_rcu_tasks_rude") and
  headArgument = 0 and callbackArgument = 1 and domain = "rcu_tasks_rude"
  or
  rcuHasName(target, "call_rcu_tasks_trace") and
  headArgument = 0 and callbackArgument = 1 and domain = "rcu_tasks_trace"
  or
  rcuHasName(target, "call_srcu") and
  headArgument = 1 and callbackArgument = 2 and domain = "srcu"
}

class RcuSetupCall extends FunctionCall {
  RcuSetupCall() {
    exists(int headArgument, int callbackArgument, string domain |
      rcuCallbackApi(
        this.getTarget(), headArgument, callbackArgument, domain
      ) and callbackArgument < this.getNumberOfArguments()
    )
  }

  int getHeadArgumentIndex() {
    rcuCallbackApi(this.getTarget(), result, _, _)
  }
  int getCallbackArgumentIndex() {
    rcuCallbackApi(this.getTarget(), _, result, _)
  }
  Expr getRcuArg() { result = this.getArgument(this.getHeadArgumentIndex()) }
  Function getDirectCallbackFunction() {
    exists(FunctionAccess access |
      access = this.getArgument(this.getCallbackArgumentIndex()).getUnconverted() and
      result = access.getTarget()
    )
    or
    exists(AddressOfExpr address, FunctionAccess access |
      address = this.getArgument(this.getCallbackArgumentIndex()).getUnconverted() and
      access = address.getOperand().getUnconverted() and
      result = access.getTarget()
    )
  }

  string getSetupKind() {
    rcuCallbackApi(this.getTarget(), _, _, result)
  }
}

class RcuDeferCall extends FunctionCall {
  RcuDeferCall() {
    exists(int headArgument, int callbackArgument, string domain |
      rcuCallbackApi(
        this.getTarget(), headArgument, callbackArgument, domain
      ) and callbackArgument < this.getNumberOfArguments()
    )
  }

  int getHeadArgumentIndex() {
    rcuCallbackApi(this.getTarget(), result, _, _)
  }
  Expr getRcuArg() { result = this.getArgument(this.getHeadArgumentIndex()) }
  string getDeferKind() { result = this.getTarget().getName() }
  string getRcuDomain() { rcuCallbackApi(this.getTarget(), _, _, result) }
}

predicate immediateRcuFreeArgument(Function target, int argumentIndex, string freeKind) {
  rcuHasName(target, "kfree") and argumentIndex = 0 and freeKind = "heap"
  or rcuHasName(target, "kfree_sensitive") and argumentIndex = 0 and freeKind = "heap_sensitive"
  or rcuHasName(target, "kfree_const") and argumentIndex = 0 and freeKind = "heap_or_const"
  or rcuHasName(target, "kzfree") and argumentIndex = 0 and freeKind = "heap_zeroed"
  or rcuHasName(target, "kvfree") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc"
  or rcuHasName(target, "kvfree_sensitive") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc_sensitive"
  or rcuHasName(target, "vfree") and argumentIndex = 0 and freeKind = "vmalloc"
  or rcuHasName(target, "vfree_atomic") and argumentIndex = 0 and freeKind = "vmalloc_atomic"
  or rcuHasName(target, "devm_kfree") and argumentIndex = 1 and freeKind = "device_managed_heap"
  or rcuHasName(target, "kmem_cache_free") and argumentIndex = 1 and freeKind = "slab_cache"
  or rcuHasName(target, "mempool_free") and argumentIndex = 0 and freeKind = "mempool"
  or rcuHasName(target, "free_percpu") and argumentIndex = 0 and freeKind = "percpu"
  or rcuHasName(target, "dma_free_coherent") and argumentIndex = 2 and freeKind = "dma_coherent"
  or rcuHasName(target, "dma_free_attrs") and argumentIndex = 2 and freeKind = "dma_attrs"
  or rcuHasName(target, "dma_free_noncoherent") and argumentIndex = 2 and freeKind = "dma_noncoherent"
  or rcuHasName(target, "dmam_free_coherent") and argumentIndex = 2 and freeKind = "device_managed_dma"
  or rcuHasName(target, "dma_pool_free") and argumentIndex = 1 and freeKind = "dma_pool"
  or rcuHasName(target, "pci_free_consistent") and argumentIndex = 2 and freeKind = "pci_consistent"
  or rcuHasName(target, "pci_pool_free") and argumentIndex = 1 and freeKind = "pci_pool"
  or rcuHasName(target, "usb_free_coherent") and argumentIndex = 2 and freeKind = "usb_coherent"
  or rcuHasName(target, "gen_pool_free") and argumentIndex = 1 and freeKind = "generic_pool"
  or rcuHasName(target, "free_pages") and argumentIndex = 0 and freeKind = "pages"
  or rcuHasName(target, "free_pages_exact") and argumentIndex = 0 and freeKind = "pages_exact"
  or rcuHasName(target, "__free_pages") and argumentIndex = 0 and freeKind = "pages_internal"
  or rcuHasName(target, "__free_page") and argumentIndex = 0 and freeKind = "page_internal"
  or rcuHasName(target, "free_page") and argumentIndex = 0 and freeKind = "page"
  or rcuHasName(target, "page_frag_free") and argumentIndex = 0 and freeKind = "page_frag"
  or rcuHasName(target, "free_netdev") and argumentIndex = 0 and freeKind = "netdev"
  or rcuHasName(target, "kmem_cache_free_bulk") and argumentIndex = 2 and freeKind = "slab_cache_bulk"
  or rcuHasName(target, "kfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_heap"
  or rcuHasName(target, "kvfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_vm"
}

class RcuFreeCall extends FunctionCall {
  RcuFreeCall() {
    exists(int argumentIndex, string freeKind |
      immediateRcuFreeArgument(this.getTarget(), argumentIndex, freeKind) and
      argumentIndex < this.getNumberOfArguments()
    )
  }

  int getFreedArgumentIndex() { immediateRcuFreeArgument(this.getTarget(), result, _) }
  Expr getFreedExpr() { result = this.getArgument(this.getFreedArgumentIndex()) }
  string getFreeKind() { immediateRcuFreeArgument(this.getTarget(), _, result) }
  string getFreeApi() { result = this.getTarget().getName() }
}

bindingset[before]
predicate rcuCfgStrictlyAfter(ControlFlowNode before, ControlFlowNode after) {
  before.getControlFlowScope() = after.getControlFlowScope() and
  before.getASuccessor+() = after
}

predicate rcuOwnerAndField(Expr rcuArg, Expr owner, Field rcuField) {
  exists(FieldAccess access |
    (
      access = rcuArg.getUnconverted()
      or exists(AddressOfExpr address |
        address = rcuArg.getUnconverted() and
        access = address.getOperand().getUnconverted()
      )
    ) and
    owner = access.getQualifier().getUnconverted() and
    rcuField = access.getTarget() and
    (
      rcuField.getType().getUnspecifiedType().hasName("rcu_head") or
      rcuField.getType().getUnspecifiedType().hasName("callback_head")
    )
  )
}

string rcuFieldIdentity(Field field) {
  result = field.getFile().getRelativePath() + ":" +
    field.getLocation().getStartLine().toString() + ":" +
    field.getLocation().getStartColumn().toString()
}

Expr rcuStripAddressExpr(Expr expression) {
  not expression.getUnconverted() instanceof AddressOfExpr and
  result = expression.getUnconverted()
  or
  exists(AddressOfExpr address |
    address = expression.getUnconverted() and
    result = address.getOperand().getUnconverted()
  )
}

bindingset[expression]
predicate rcuExprRootAndPath(
  Expr expression, Variable root,
  string identityPath, string displayPath, int depth
) {
  depth = 0 and
  exists(VariableAccess access |
    access = rcuStripAddressExpr(expression) and root = access.getTarget()
  ) and
  identityPath = "" and displayPath = ""
  or
  depth = 1 and rcuMaxTreeFieldDepth() >= 1 and
  exists(FieldAccess f1, VariableAccess access |
    f1 = rcuStripAddressExpr(expression) and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = rcuFieldIdentity(f1.getTarget()) and
    displayPath = f1.getTarget().getName()
  )
  or
  depth = 2 and rcuMaxTreeFieldDepth() >= 2 and
  exists(FieldAccess f1, FieldAccess f2, VariableAccess access |
    f2 = rcuStripAddressExpr(expression) and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = rcuFieldIdentity(f1.getTarget()) + "/" + rcuFieldIdentity(f2.getTarget()) and
    displayPath = f1.getTarget().getName() + "." + f2.getTarget().getName()
  )
  or
  depth = 3 and rcuMaxTreeFieldDepth() >= 3 and
  exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, VariableAccess access |
    f3 = rcuStripAddressExpr(expression) and
    f2 = f3.getQualifier().getUnconverted() and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = rcuFieldIdentity(f1.getTarget()) + "/" +
      rcuFieldIdentity(f2.getTarget()) + "/" + rcuFieldIdentity(f3.getTarget()) and
    displayPath = f1.getTarget().getName() + "." +
      f2.getTarget().getName() + "." + f3.getTarget().getName()
  )
}

predicate rcuVariablePointsToType(Variable variable, Type targetType) {
  exists(PointerType pointer |
    pointer = variable.getType().getUnspecifiedType() and
    pointer.getBaseType().getUnspecifiedType() = targetType.getUnspecifiedType()
  )
}

bindingset[leftIdentity, rightIdentity]
string rcuJoinIdentityPath(string leftIdentity, string rightIdentity) {
  leftIdentity = "" and result = rightIdentity
  or rightIdentity = "" and result = leftIdentity
  or leftIdentity != "" and rightIdentity != "" and
    result = leftIdentity + "/" + rightIdentity
}

bindingset[leftDisplay, rightDisplay]
string rcuJoinDisplayPath(string leftDisplay, string rightDisplay) {
  leftDisplay = "" and result = rightDisplay
  or rightDisplay = "" and result = leftDisplay
  or leftDisplay != "" and rightDisplay != "" and
    result = leftDisplay + "." + rightDisplay
}

bindingset[prefix, full]
predicate rcuPathPrefix(string prefix, string full) {
  prefix = "" or prefix = full or full.indexOf(prefix + "/") = 0
}

predicate rcuTerminalRealFieldUse(FieldAccess use) {
  not exists(AddressOfExpr address |
    address.getOperand().getUnconverted() = use.getUnconverted()
  ) and
  not exists(FieldAccess outer |
    outer.getQualifier().getUnconverted() = use.getUnconverted()
  ) and
  (use.isRValue() or use.isModified() or use.isUsedAsLValue())
}

/** The declared rcu field and registered rcu callback are exact. */
predicate rcuSetupMatchesField(
  RcuSetupCall setup, Field rcuField, Function callback
) {
  exists(Expr setupOwner |
    rcuOwnerAndField(setup.getRcuArg(), setupOwner, rcuField) and
    callback = setup.getDirectCallbackFunction()
  )
}

/** Direct call_rcu*(&owner->rcu, callback). */
pragma[noinline]
predicate rcuDirectLifecycleAnchor(
  RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(string identityPath, string displayPath, int depth |
    setup = defer and
    rcuSetupMatchesField(setup, rcuField, callback) and
    setup.getFile() = defer.getFile() and
    rcuOwnerAndField(defer.getRcuArg(), lifecycleOwner, rcuField) and
    rcuExprRootAndPath(
      lifecycleOwner, lifecycleRoot, identityPath, displayPath, depth
    ) and identityPath = "" and
    rcuVariablePointsToType(lifecycleRoot, rcuField.getDeclaringType()) and
    flowEntry = defer
  )
}

/** Caller passes owner to a one-hop wrapper that performs call_rcu*. */
pragma[noinline]
predicate rcuOwnerDeferWrapperLifecycleAnchor(
  RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(
    Expr deferOwner, Variable deferRoot,
    string deferIdentity, string deferDisplay, int deferDepth,
    FunctionCall wrapper, int argumentIndex,
    Variable callerRoot, string argumentIdentity, string argumentDisplay,
    int argumentDepth, Parameter calleeRoot
  |
    rcuMaxWrapperDepth() >= 1 and
    setup = defer and
    rcuSetupMatchesField(setup, rcuField, callback) and
    setup.getFile() = defer.getFile() and
    rcuOwnerAndField(defer.getRcuArg(), deferOwner, rcuField) and
    rcuExprRootAndPath(
      deferOwner, deferRoot, deferIdentity, deferDisplay, deferDepth
    ) and deferIdentity = "" and
    calleeRoot = deferRoot and
    wrapper.getTarget() = defer.getEnclosingFunction() and
    calleeRoot = wrapper.getTarget().getParameter(argumentIndex) and
    rcuExprRootAndPath(
      wrapper.getArgument(argumentIndex), callerRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and argumentIdentity = "" and
    rcuVariablePointsToType(callerRoot, rcuField.getDeclaringType()) and
    lifecycleOwner = wrapper.getArgument(argumentIndex).getUnconverted() and
    lifecycleRoot = callerRoot and flowEntry = wrapper
  )
}

/** Caller passes &owner->rcu to a one-hop wrapper taking struct rcu *. */
pragma[noinline]
predicate rcuFieldDeferWrapperLifecycleAnchor(
  RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(
    FunctionCall wrapper, int argumentIndex, Parameter calleeRcu,
    VariableAccess deferParameter,
    string ownerIdentity, string ownerDisplay, int ownerDepth
  |
    rcuMaxWrapperDepth() >= 1 and
    setup = defer and
    rcuSetupMatchesField(setup, rcuField, callback) and
    setup.getFile() = defer.getFile() and
    wrapper.getTarget() = defer.getEnclosingFunction() and
    calleeRcu = wrapper.getTarget().getParameter(argumentIndex) and
    deferParameter = defer.getRcuArg().getUnconverted() and
    deferParameter.getTarget() = calleeRcu and
    rcuOwnerAndField(wrapper.getArgument(argumentIndex), lifecycleOwner, rcuField) and
    rcuExprRootAndPath(
      lifecycleOwner, lifecycleRoot, ownerIdentity, ownerDisplay, ownerDepth
    ) and ownerIdentity = "" and
    rcuVariablePointsToType(lifecycleRoot, rcuField.getDeclaringType()) and
    flowEntry = wrapper
  )
}

pragma[noinline]
predicate rcuAnyLifecycleAnchor(
  RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry, int deferWrapperDepth, string lifecycleBinding
) {
  rcuDirectLifecycleAnchor(
    setup, defer, rcuField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and deferWrapperDepth = 0 and lifecycleBinding = "direct_defer_exact_owner"
  or
  rcuOwnerDeferWrapperLifecycleAnchor(
    setup, defer, rcuField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and deferWrapperDepth = 1 and lifecycleBinding = "owner_defer_wrapper_exact_parameter"
  or
  rcuFieldDeferWrapperLifecycleAnchor(
    setup, defer, rcuField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and deferWrapperDepth = 1 and lifecycleBinding = "rcu_field_defer_wrapper_exact_parameter"
}

/** container_of with the exact embedded rcu Field. */
predicate rcuModernCallbackOwner(
  Function callback, Field rcuField, Variable callbackOwner
) {
  exists(MacroInvocation recover, LocalVariable local, Initializer initializer |
    recover.getEnclosingFunction() = callback and
    (recover.getMacroName() = "container_of" or
     recover.getMacroName() = "container_of_const" or
     recover.getMacroName() = "from_rcu_head") and
    recover.getUnexpandedArgument(2) = rcuField.getName() and
    local = callbackOwner and local.getFunction() = callback and
    initializer = local.getInitializer() and (initializer.getExpr() = recover.getExpr() or kernelLocalValueFlow(recover.getExpr(), local.getAnAccess())) and
    rcuVariablePointsToType(local, rcuField.getDeclaringType())
  )
}

predicate rcuCallbackOwnerSeed(
  RcuSetupCall setup, Function callback, Field rcuField,
  Variable callbackOwner, string recoveryKind
) {
  rcuSetupMatchesField(setup, rcuField, callback) and
  rcuModernCallbackOwner(callback, rcuField, callbackOwner) and
  recoveryKind = "container_of_exact_rcu_field"
}

Function rcuVariableFunction(Variable variable) {
  exists(Parameter parameter |
    variable = parameter and result = parameter.getFunction()
  )
  or
  exists(LocalVariable local |
    variable = local and result = local.getFunction()
  )
}

pragma[noinline]
predicate rcuDirectCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(int useDepth |
    use.getEnclosingFunction() = rcuVariableFunction(callbackOwner) and
    rcuTerminalRealFieldUse(use) and
    rcuExprRootAndPath(
      use, callbackOwner, useIdentityPath, useDisplayPath, useDepth
    )
  )
}

pragma[noinline]
predicate rcuOneHopCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    rcuMaxWrapperDepth() >= 1 and
    helperCall.getEnclosingFunction() = rcuVariableFunction(callbackOwner) and
    rcuExprRootAndPath(
      helperCall.getArgument(argumentIndex), callbackOwner,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    use.getEnclosingFunction() = helperRoot.getFunction() and
    rcuTerminalRealFieldUse(use) and
    rcuExprRootAndPath(
      use, helperRoot, helperIdentity, helperDisplay, helperDepth
    ) and
    useIdentityPath = rcuJoinIdentityPath(argumentIdentity, helperIdentity) and
    useDisplayPath = rcuJoinDisplayPath(argumentDisplay, helperDisplay)
  )
}

pragma[noinline]
predicate rcuAnyCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath, int callbackCallDepth
) {
  rcuDirectCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 0
  or
  rcuOneHopCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 1
}

/**
 * Materialize direct call_rcu(&owner->head, callback) registrations before
 * expanding wrapper callers or callback field accesses.  RCU registrations
 * are common enough that keeping all three joins in one predicate makes the
 * evaluator scan the global FieldAccess relation repeatedly.
 */
newtype TRcuDirectRegistration =
  MkRcuDirectRegistration(
    RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    Expr registrationOwner, Variable registrationRoot
  ) {
    exists(string identityPath, string displayPath, int depth |
      setup = defer and
      rcuSetupMatchesField(setup, rcuField, callback) and
      rcuOwnerAndField(defer.getRcuArg(), registrationOwner, rcuField) and
      rcuExprRootAndPath(
        registrationOwner, registrationRoot,
        identityPath, displayPath, depth
      ) and identityPath = "" and
      rcuVariablePointsToType(registrationRoot, rcuField.getDeclaringType()) and
      rcuCallbackOwnerSeed(
        setup, callback, rcuField, callbackOwner, callbackRecovery
      )
    )
  }

class RcuDirectRegistration extends TRcuDirectRegistration {
  RcuSetupCall setup;
  RcuDeferCall defer;
  Field rcuField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  Expr registrationOwner;
  Variable registrationRoot;

  RcuDirectRegistration() {
    this = MkRcuDirectRegistration(
      setup, defer, rcuField, callback, callbackOwner, callbackRecovery,
      registrationOwner, registrationRoot
    )
  }

  RcuSetupCall getSetup() { result = setup }
  RcuDeferCall getDefer() { result = defer }
  Field getRcuField() { result = rcuField }
  Function getCallback() { result = callback }
  Variable getCallbackOwner() { result = callbackOwner }
  string getCallbackRecovery() { result = callbackRecovery }
  Expr getRegistrationOwner() { result = registrationOwner }
  Variable getRegistrationRoot() { result = registrationRoot }
  string toString() { result = "rcu-direct-registration" }
}

/**
 * A one-hop caller of a function whose owner parameter is passed directly to
 * call_rcu.  The wrapper argument must be the caller's owner variable itself;
 * field-wrapper arguments are modeled separately below.
 */
newtype TRcuOwnerWrapperRegistration =
  MkRcuOwnerWrapperRegistration(
    RcuDirectRegistration registration, FunctionCall flowEntry,
    Expr lifecycleOwner, Variable lifecycleRoot
  ) {
    exists(Parameter calleeRoot, int argumentIndex, VariableAccess callerAccess |
      calleeRoot = registration.getRegistrationRoot() and
      flowEntry.getTarget() = calleeRoot.getFunction() and
      flowEntry.getFile() = registration.getDefer().getFile() and
      calleeRoot = flowEntry.getTarget().getParameter(argumentIndex) and
      callerAccess = rcuStripAddressExpr(flowEntry.getArgument(argumentIndex)) and
      lifecycleRoot = callerAccess.getTarget() and
      rcuVariablePointsToType(
        lifecycleRoot, registration.getRcuField().getDeclaringType()
      ) and
      lifecycleOwner = flowEntry.getArgument(argumentIndex).getUnconverted()
    )
  }

class RcuOwnerWrapperRegistration extends TRcuOwnerWrapperRegistration {
  RcuDirectRegistration registration;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  Variable lifecycleRoot;

  RcuOwnerWrapperRegistration() {
    this = MkRcuOwnerWrapperRegistration(
      registration, flowEntry, lifecycleOwner, lifecycleRoot
    )
  }

  RcuDirectRegistration getRegistration() { result = registration }
  FunctionCall getFlowEntry() { result = flowEntry }
  Expr getLifecycleOwner() { result = lifecycleOwner }
  Variable getLifecycleRoot() { result = lifecycleRoot }
  string toString() { result = "rcu-owner-wrapper-registration" }
}

predicate rcuVariablePointsToHead(Variable variable) {
  exists(PointerType pointer |
    pointer = variable.getType().getUnspecifiedType() and
    (
      pointer.getBaseType().getUnspecifiedType().hasName("rcu_head") or
      pointer.getBaseType().getUnspecifiedType().hasName("callback_head")
    )
  )
}

/** call_rcu(head_parameter, callback) inside a one-hop field wrapper. */
newtype TRcuFieldParameterRegistration =
  MkRcuFieldParameterRegistration(
    RcuSetupCall setup, RcuDeferCall defer,
    Function callback, Parameter headParameter
  ) {
    exists(VariableAccess headAccess |
      setup = defer and
      callback = setup.getDirectCallbackFunction() and
      headAccess = defer.getRcuArg().getUnconverted() and
      headParameter = headAccess.getTarget() and
      headParameter.getFunction() = defer.getEnclosingFunction() and
      rcuVariablePointsToHead(headParameter)
    )
  }

class RcuFieldParameterRegistration extends TRcuFieldParameterRegistration {
  RcuSetupCall setup;
  RcuDeferCall defer;
  Function callback;
  Parameter headParameter;

  RcuFieldParameterRegistration() {
    this = MkRcuFieldParameterRegistration(
      setup, defer, callback, headParameter
    )
  }

  RcuSetupCall getSetup() { result = setup }
  RcuDeferCall getDefer() { result = defer }
  Function getCallback() { result = callback }
  Parameter getHeadParameter() { result = headParameter }
  string toString() { result = "rcu-field-parameter-registration" }
}

/** A concrete caller of a wrapper whose parameter is the embedded RCU head. */
newtype TRcuFieldWrapperRegistration =
  MkRcuFieldWrapperRegistration(
    RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner, Variable lifecycleRoot
  ) {
    exists(
      RcuFieldParameterRegistration registration,
      int argumentIndex, string identityPath, string displayPath, int depth
    |
      setup = registration.getSetup() and defer = registration.getDefer() and
      callback = registration.getCallback() and
      flowEntry.getTarget() = defer.getEnclosingFunction() and
      flowEntry.getFile() = defer.getFile() and
      registration.getHeadParameter() = flowEntry.getTarget().getParameter(argumentIndex) and
      rcuOwnerAndField(flowEntry.getArgument(argumentIndex), lifecycleOwner, rcuField) and
      rcuExprRootAndPath(
        lifecycleOwner, lifecycleRoot, identityPath, displayPath, depth
      ) and identityPath = "" and
      rcuVariablePointsToType(lifecycleRoot, rcuField.getDeclaringType()) and
      rcuModernCallbackOwner(callback, rcuField, callbackOwner) and
      callbackRecovery = "container_of_exact_rcu_field"
    )
  }

class RcuFieldWrapperRegistration extends TRcuFieldWrapperRegistration {
  RcuSetupCall setup;
  RcuDeferCall defer;
  Field rcuField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  Variable lifecycleRoot;

  RcuFieldWrapperRegistration() {
    this = MkRcuFieldWrapperRegistration(
      setup, defer, rcuField, callback, callbackOwner, callbackRecovery,
      flowEntry, lifecycleOwner, lifecycleRoot
    )
  }

  RcuSetupCall getSetup() { result = setup }
  RcuDeferCall getDefer() { result = defer }
  Field getRcuField() { result = rcuField }
  Function getCallback() { result = callback }
  Variable getCallbackOwner() { result = callbackOwner }
  string getCallbackRecovery() { result = callbackRecovery }
  FunctionCall getFlowEntry() { result = flowEntry }
  Expr getLifecycleOwner() { result = lifecycleOwner }
  Variable getLifecycleRoot() { result = lifecycleRoot }
  string toString() { result = "rcu-field-wrapper-registration" }
}

/**
 * Materialize the rare exact setup/field/callback/lifecycle binding before
 * scanning callback bodies.  On large kernel databases this prevents the
 * optimizer from expanding every FieldAccess before the rcu seed is known.
 */
newtype TRcuBoundLifecycle =
  MkRcuBoundLifecycle(
    RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner, Variable lifecycleRoot,
    int deferWrapperDepth, string lifecycleBinding
  ) {
    exists(RcuDirectRegistration registration |
      setup = registration.getSetup() and
      defer = registration.getDefer() and
      rcuField = registration.getRcuField() and
      callback = registration.getCallback() and
      callbackOwner = registration.getCallbackOwner() and
      callbackRecovery = registration.getCallbackRecovery() and
      (
        flowEntry = defer and
        lifecycleOwner = registration.getRegistrationOwner() and
        lifecycleRoot = registration.getRegistrationRoot() and
        deferWrapperDepth = 0 and lifecycleBinding = "direct_defer_exact_owner"
        or
        exists(
          Parameter calleeRoot, FunctionCall wrapper, int argumentIndex,
          Variable callerRoot, string identityPath, string displayPath, int depth
        |
          rcuMaxWrapperDepth() >= 1 and
          calleeRoot = registration.getRegistrationRoot() and
          wrapper.getTarget() = calleeRoot.getFunction() and
          wrapper.getFile() = defer.getFile() and
          calleeRoot = wrapper.getTarget().getParameter(argumentIndex) and
          rcuExprRootAndPath(
            wrapper.getArgument(argumentIndex), callerRoot,
            identityPath, displayPath, depth
          ) and identityPath = "" and
          rcuVariablePointsToType(callerRoot, rcuField.getDeclaringType()) and
          flowEntry = wrapper and
          lifecycleOwner = wrapper.getArgument(argumentIndex).getUnconverted() and
          lifecycleRoot = callerRoot and deferWrapperDepth = 1 and
          lifecycleBinding = "owner_defer_wrapper_exact_parameter"
        )
      )
    )
    or
    exists(
      RcuFieldParameterRegistration registration,
      FunctionCall wrapper, int argumentIndex,
      Expr owner, Field field, Variable root,
      string identityPath, string displayPath, int depth,
      Variable recoveredOwner
    |
      rcuMaxWrapperDepth() >= 1 and
      setup = registration.getSetup() and defer = registration.getDefer() and
      callback = registration.getCallback() and
      wrapper.getTarget() = defer.getEnclosingFunction() and
      wrapper.getFile() = defer.getFile() and
      registration.getHeadParameter() = wrapper.getTarget().getParameter(argumentIndex) and
      rcuOwnerAndField(wrapper.getArgument(argumentIndex), owner, field) and
      rcuExprRootAndPath(
        owner, root, identityPath, displayPath, depth
      ) and identityPath = "" and
      rcuVariablePointsToType(root, field.getDeclaringType()) and
      rcuModernCallbackOwner(callback, field, recoveredOwner) and
      rcuField = field and callbackOwner = recoveredOwner and
      callbackRecovery = "container_of_exact_rcu_field" and
      flowEntry = wrapper and lifecycleOwner = owner and lifecycleRoot = root and
      deferWrapperDepth = 1 and
      lifecycleBinding = "rcu_field_defer_wrapper_exact_parameter"
    )
  }

class RcuBoundLifecycle extends TRcuBoundLifecycle {
  RcuSetupCall setup;
  RcuDeferCall defer;
  Field rcuField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  Variable lifecycleRoot;
  int deferWrapperDepth;
  string lifecycleBinding;

  RcuBoundLifecycle() {
    this = MkRcuBoundLifecycle(
      setup, defer, rcuField, callback, callbackOwner, callbackRecovery,
      flowEntry, lifecycleOwner, lifecycleRoot,
      deferWrapperDepth, lifecycleBinding
    )
  }

  RcuSetupCall getSetup() { result = setup }
  RcuDeferCall getDefer() { result = defer }
  Field getRcuField() { result = rcuField }
  Function getCallback() { result = callback }
  Variable getCallbackOwner() { result = callbackOwner }
  string getCallbackRecovery() { result = callbackRecovery }
  FunctionCall getFlowEntry() { result = flowEntry }
  Expr getLifecycleOwner() { result = lifecycleOwner }
  Variable getLifecycleRoot() { result = lifecycleRoot }
  int getDeferWrapperDepth() { result = deferWrapperDepth }
  string getLifecycleBinding() { result = lifecycleBinding }
  string toString() { result = "rcu-bound-lifecycle" }
}

/** Scan callback fields once per exact direct registration, before callers. */
newtype TRcuDirectRegistrationUse =
  MkRcuDirectRegistrationUse(
    RcuDirectRegistration registration, FieldAccess use,
    string useIdentityPath, string useDisplayPath, int callbackCallDepth
  ) {
    rcuAnyCallbackRealUse(
      registration.getCallbackOwner(), use,
      useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

class RcuDirectRegistrationUse extends TRcuDirectRegistrationUse {
  RcuDirectRegistration registration;
  FieldAccess use;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;

  RcuDirectRegistrationUse() {
    this = MkRcuDirectRegistrationUse(
      registration, use, useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

  RcuDirectRegistration getRegistration() { result = registration }
  FieldAccess getUse() { result = use }
  string getUseIdentityPath() { result = useIdentityPath }
  string getUseDisplayPath() { result = useDisplayPath }
  int getCallbackCallDepth() { result = callbackCallDepth }
  string toString() { result = "rcu-direct-registration-use" }
}

/** Real callback access attached to one concrete owner-wrapper call site. */
newtype TRcuOwnerWrapperUse =
  MkRcuOwnerWrapperUse(
    RcuOwnerWrapperRegistration wrapper, FieldAccess use,
    string useIdentityPath, string useDisplayPath, int callbackCallDepth
  ) {
    rcuAnyCallbackRealUse(
      wrapper.getRegistration().getCallbackOwner(), use,
      useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

class RcuOwnerWrapperUse extends TRcuOwnerWrapperUse {
  RcuOwnerWrapperRegistration wrapper;
  FieldAccess use;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;

  RcuOwnerWrapperUse() {
    this = MkRcuOwnerWrapperUse(
      wrapper, use, useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

  RcuOwnerWrapperRegistration getWrapper() { result = wrapper }
  FieldAccess getUse() { result = use }
  string getUseIdentityPath() { result = useIdentityPath }
  string getUseDisplayPath() { result = useDisplayPath }
  int getCallbackCallDepth() { result = callbackCallDepth }
  string toString() { result = "rcu-owner-wrapper-use" }
}

/** Real callback access for a registration recovered at a field-wrapper call. */
newtype TRcuFieldWrapperUse =
  MkRcuFieldWrapperUse(
    RcuFieldWrapperRegistration registration, FieldAccess use,
    string useIdentityPath, string useDisplayPath, int callbackCallDepth
  ) {
    rcuAnyCallbackRealUse(
      registration.getCallbackOwner(), use,
      useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

class RcuFieldWrapperUse extends TRcuFieldWrapperUse {
  RcuFieldWrapperRegistration registration;
  FieldAccess use;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;

  RcuFieldWrapperUse() {
    this = MkRcuFieldWrapperUse(
      registration, use, useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

  RcuFieldWrapperRegistration getRegistration() { result = registration }
  FieldAccess getUse() { result = use }
  string getUseIdentityPath() { result = useIdentityPath }
  string getUseDisplayPath() { result = useDisplayPath }
  int getCallbackCallDepth() { result = callbackCallDepth }
  string toString() { result = "rcu-field-wrapper-use" }
}

/** Expand only callers of a registration that is already bound by a real use. */
pragma[noinline]
predicate rcuDirectRegistrationFlow(
  RcuDirectRegistration registration,
  FunctionCall flowEntry, Expr lifecycleOwner, Variable lifecycleRoot,
  int deferWrapperDepth, string lifecycleBinding
) {
  flowEntry = registration.getDefer() and
  lifecycleOwner = registration.getRegistrationOwner() and
  lifecycleRoot = registration.getRegistrationRoot() and
  deferWrapperDepth = 0 and lifecycleBinding = "direct_defer_exact_owner"
  or
  exists(RcuOwnerWrapperRegistration wrapper |
    rcuMaxWrapperDepth() >= 1 and
    wrapper.getRegistration() = registration and
    flowEntry = wrapper.getFlowEntry() and
    lifecycleOwner = wrapper.getLifecycleOwner() and
    lifecycleRoot = wrapper.getLifecycleRoot() and
    deferWrapperDepth = 1 and
    lifecycleBinding = "owner_defer_wrapper_exact_parameter"
  )
}

/** Materialize only concrete terminal callback accesses for the bound seed. */
newtype TRcuBoundUse =
  MkRcuBoundUse(
    RcuBoundLifecycle lifecycle, FieldAccess use,
    string useIdentityPath, string useDisplayPath, int callbackCallDepth
  ) {
    exists(RcuDirectRegistrationUse registrationUse |
      lifecycle.getSetup() = registrationUse.getRegistration().getSetup() and
      lifecycle.getDefer() = registrationUse.getRegistration().getDefer() and
      lifecycle.getRcuField() = registrationUse.getRegistration().getRcuField() and
      lifecycle.getCallbackOwner() = registrationUse.getRegistration().getCallbackOwner() and
      use = registrationUse.getUse() and
      useIdentityPath = registrationUse.getUseIdentityPath() and
      useDisplayPath = registrationUse.getUseDisplayPath() and
      callbackCallDepth = registrationUse.getCallbackCallDepth()
    )
    or
    lifecycle.getLifecycleBinding() = "rcu_field_defer_wrapper_exact_parameter" and
    rcuAnyCallbackRealUse(
      lifecycle.getCallbackOwner(), use,
      useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

class RcuBoundUse extends TRcuBoundUse {
  RcuBoundLifecycle lifecycle;
  FieldAccess use;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;

  RcuBoundUse() {
    this = MkRcuBoundUse(
      lifecycle, use, useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

  RcuBoundLifecycle getLifecycle() { result = lifecycle }
  FieldAccess getUse() { result = use }
  string getUseIdentityPath() { result = useIdentityPath }
  string getUseDisplayPath() { result = useDisplayPath }
  int getCallbackCallDepth() { result = callbackCallDepth }
  string toString() { result = "rcu-bound-use" }
}

predicate rcuTeardownLikeFunction(Function function) {
  function.getName().matches("%remove%") or function.getName().matches("%detach%") or
  function.getName().matches("%cleanup%") or function.getName().matches("%destroy%") or
  function.getName().matches("%release%") or function.getName().matches("%shutdown%") or
  function.getName().matches("%unregister%") or function.getName().matches("%deinit%") or
  function.getName().matches("%exit%") or function.getName().matches("%stop%") or
  function.getName().matches("%close%") or function.getName().matches("free_%") or
  function.getName().matches("%_free")
}

/** Functions executed as the callback body or as its modeled one-hop helper. */
predicate rcuCallbackExecutionFunction(Function callback, Function function) {
  function = callback
  or
  exists(FunctionCall helperCall |
    helperCall.getEnclosingFunction() = callback and
    helperCall.getTarget() = function
  )
}

/** A free expression indexed by its enclosing function and syntactic root. */
newtype TRcuDirectFreeByRoot =
  MkRcuDirectFreeByRoot(
    Function scope, Variable root, RcuFreeCall free,
    string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
  ) {
    scope = free.getEnclosingFunction() and
    rcuExprRootAndPath(
      free.getFreedExpr(), root,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

class RcuDirectFreeByRoot extends TRcuDirectFreeByRoot {
  Function scope;
  Variable root;
  RcuFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freedFieldDepth;

  RcuDirectFreeByRoot() {
    this = MkRcuDirectFreeByRoot(
      scope, root, free, freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

  Function getScope() { result = scope }
  Variable getRoot() { result = root }
  RcuFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string toString() { result = "rcu-direct-free-by-root" }
}

/**
 * Sparse, use-independent teardown/free seeds.
 *
 * Keeping these tuples independent of RcuBoundUse is important: otherwise
 * the evaluator may repeatedly join every callback FieldAccess with every
 * free call before it can apply the file, owner-type, and path restrictions.
 */
newtype TRcuCrossDirectFreeSeed =
  MkRcuCrossDirectFreeSeed(
    Type ownerType, Function teardown, RcuFreeCall free,
    string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
  ) {
    teardown = free.getEnclosingFunction() and
    rcuTeardownLikeFunction(teardown) and
    exists(Variable freeRoot, PointerType ownerPointer |
      rcuExprRootAndPath(
        free.getFreedExpr(), freeRoot,
        freeIdentityPath, freeDisplayPath, freedFieldDepth
      ) and
      ownerPointer = freeRoot.getType().getUnspecifiedType() and
      ownerType = ownerPointer.getBaseType().getUnspecifiedType()
    )
  }

class RcuCrossDirectFreeSeed extends TRcuCrossDirectFreeSeed {
  Type ownerType;
  Function teardown;
  RcuFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freedFieldDepth;

  RcuCrossDirectFreeSeed() {
    this = MkRcuCrossDirectFreeSeed(
      ownerType, teardown, free,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

  Type getOwnerType() { result = ownerType }
  Function getTeardown() { result = teardown }
  RcuFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string toString() { result = "rcu-cross-direct-free-seed" }
}

newtype TRcuCrossOneHopFreeSeed =
  MkRcuCrossOneHopFreeSeed(
    Type ownerType, Function teardown, RcuFreeCall free,
    string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
  ) {
    exists(
      FunctionCall helperCall, int argumentIndex,
      Variable teardownRoot, PointerType ownerPointer,
      string argumentIdentity, string argumentDisplay, int argumentDepth,
      Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
    |
      rcuMaxWrapperDepth() >= 1 and
      teardown = helperCall.getEnclosingFunction() and
      rcuTeardownLikeFunction(teardown) and
      not helperCall instanceof RcuFreeCall and
      rcuExprRootAndPath(
        helperCall.getArgument(argumentIndex), teardownRoot,
        argumentIdentity, argumentDisplay, argumentDepth
      ) and
      ownerPointer = teardownRoot.getType().getUnspecifiedType() and
      ownerType = ownerPointer.getBaseType().getUnspecifiedType() and
      helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
      free.getEnclosingFunction() = helperRoot.getFunction() and
      rcuExprRootAndPath(
        free.getFreedExpr(), helperRoot,
        helperIdentity, helperDisplay, helperDepth
      ) and
      freeIdentityPath = rcuJoinIdentityPath(argumentIdentity, helperIdentity) and
      freeDisplayPath = rcuJoinDisplayPath(argumentDisplay, helperDisplay) and
      freedFieldDepth = argumentDepth + helperDepth
    )
  }

class RcuCrossOneHopFreeSeed extends TRcuCrossOneHopFreeSeed {
  Type ownerType;
  Function teardown;
  RcuFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freedFieldDepth;

  RcuCrossOneHopFreeSeed() {
    this = MkRcuCrossOneHopFreeSeed(
      ownerType, teardown, free,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

  Type getOwnerType() { result = ownerType }
  Function getTeardown() { result = teardown }
  RcuFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string toString() { result = "rcu-cross-one-hop-free-seed" }
}

predicate rcuCallerDirectFreeSeed(
  FunctionCall flowEntry, Variable lifecycleRoot,
  RcuFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  free.getFile() = flowEntry.getFile() and
  free.getEnclosingFunction() = flowEntry.getEnclosingFunction() and
  free.getLocation().getStartLine() > flowEntry.getLocation().getStartLine() and
  rcuExprRootAndPath(
    free.getFreedExpr(), lifecycleRoot,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  )
}

predicate rcuCallerOneHopFreeSeed(
  FunctionCall flowEntry, Variable lifecycleRoot,
  RcuFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    rcuMaxWrapperDepth() >= 1 and
    helperCall.getFile() = flowEntry.getFile() and
    helperCall.getEnclosingFunction() = flowEntry.getEnclosingFunction() and
    helperCall.getLocation().getStartLine() > flowEntry.getLocation().getStartLine() and
    not helperCall instanceof RcuFreeCall and
    rcuExprRootAndPath(
      helperCall.getArgument(argumentIndex), lifecycleRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    free.getEnclosingFunction() = helperRoot.getFunction() and
    rcuExprRootAndPath(
      free.getFreedExpr(), helperRoot,
      helperIdentity, helperDisplay, helperDepth
    ) and
    freeIdentityPath = rcuJoinIdentityPath(argumentIdentity, helperIdentity) and
    freeDisplayPath = rcuJoinDisplayPath(argumentDisplay, helperDisplay) and
    freedFieldDepth = argumentDepth + helperDepth
  )
}

bindingset[useIdentityPath]
predicate rcuCallerDirectFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  string useIdentityPath, RcuFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  rcuCallerDirectFreeSeed(
    flowEntry, lifecycleRoot, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and
  rcuPathPrefix(freeIdentityPath, useIdentityPath)
}

bindingset[useIdentityPath]
predicate rcuCallerOneHopFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  string useIdentityPath, RcuFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  rcuCallerOneHopFreeSeed(
    flowEntry, lifecycleRoot, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and
  rcuPathPrefix(freeIdentityPath, useIdentityPath)
}

bindingset[useIdentityPath]
predicate rcuCrossLifecycleDirectFreeFinding(
  FunctionCall flowEntry, Field rcuField, Function callback,
  string useIdentityPath, RcuFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(RcuCrossDirectFreeSeed seed |
    seed.getTeardown() != flowEntry.getEnclosingFunction() and
    not rcuCallbackExecutionFunction(callback, seed.getTeardown()) and
    seed.getTeardown().getFile() = flowEntry.getFile() and
    seed.getOwnerType() = rcuField.getDeclaringType().getUnspecifiedType() and
    free = seed.getFree() and
    freeIdentityPath = seed.getFreeIdentityPath() and
    freeDisplayPath = seed.getFreeDisplayPath() and
    freedFieldDepth = seed.getFreedFieldDepth() and
    rcuPathPrefix(seed.getFreeIdentityPath(), useIdentityPath)
  )
}

bindingset[useIdentityPath]
predicate rcuCrossLifecycleOneHopFreeFinding(
  FunctionCall flowEntry, Field rcuField, Function callback,
  string useIdentityPath, RcuFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(RcuCrossOneHopFreeSeed seed |
    seed.getTeardown() != flowEntry.getEnclosingFunction() and
    not rcuCallbackExecutionFunction(callback, seed.getTeardown()) and
    seed.getTeardown().getFile() = flowEntry.getFile() and
    seed.getOwnerType() = rcuField.getDeclaringType().getUnspecifiedType() and
    free = seed.getFree() and
    freeIdentityPath = seed.getFreeIdentityPath() and
    freeDisplayPath = seed.getFreeDisplayPath() and
    freedFieldDepth = seed.getFreedFieldDepth() and
    rcuPathPrefix(seed.getFreeIdentityPath(), useIdentityPath)
  )
}

bindingset[useIdentityPath]
predicate rcuAnyFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field rcuField, Function callback,
  string useIdentityPath, RcuFreeCall free,
  string freeIdentityPath, string freeDisplayPath,
  int freeCallDepth, int freedFieldDepth, string flowMode
) {
  rcuCallerDirectFreeFinding(
    flowEntry, lifecycleRoot, useIdentityPath, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "direct_cfg_free"
  or
  rcuCallerOneHopFreeFinding(
    flowEntry, lifecycleRoot, useIdentityPath, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "caller_one_hop_free"
  or
  rcuCrossLifecycleDirectFreeFinding(
    flowEntry, rcuField, callback,
    useIdentityPath, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "cross_lifecycle_teardown_root"
  or
  rcuCrossLifecycleOneHopFreeFinding(
    flowEntry, rcuField, callback,
    useIdentityPath, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "cross_lifecycle_one_hop_free"
}

/**
 * Wrapper call sites contribute only caller-local frees.  Cross-lifecycle
 * teardown matching is anchored once at the underlying registration, so
 * repeating it for every wrapper caller would add no new semantic finding.
 */
bindingset[useIdentityPath]
predicate rcuWrapperCallerFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, string useIdentityPath,
  RcuFreeCall free, string freeIdentityPath, string freeDisplayPath,
  int freeCallDepth, int freedFieldDepth, string flowMode
) {
  rcuCallerDirectFreeFinding(
    flowEntry, lifecycleRoot, useIdentityPath, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "direct_cfg_free"
  or
  rcuCallerOneHopFreeFinding(
    flowEntry, lifecycleRoot, useIdentityPath, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "caller_one_hop_free"
}

/** Materialize wrapper/free pairs before joining callback field accesses. */
newtype TRcuOwnerWrapperFreeSeed =
  MkRcuOwnerWrapperFreeSeed(
    RcuDirectRegistration registration, FunctionCall flowEntry,
    Expr lifecycleOwner, Variable lifecycleRoot, RcuFreeCall free,
    string freeIdentityPath, string freeDisplayPath,
    int freeCallDepth, int freedFieldDepth, string flowMode
  ) {
    exists(
      Parameter calleeRoot, int argumentIndex,
      VariableAccess callerAccess, VariableAccess freeAccess
    |
      calleeRoot = registration.getRegistrationRoot() and
      flowEntry.getTarget() = calleeRoot.getFunction() and
      flowEntry.getFile() = registration.getDefer().getFile() and
      calleeRoot = flowEntry.getTarget().getParameter(argumentIndex) and
      callerAccess = rcuStripAddressExpr(flowEntry.getArgument(argumentIndex)) and
      lifecycleRoot = callerAccess.getTarget() and
      rcuVariablePointsToType(
        lifecycleRoot, registration.getRcuField().getDeclaringType()
      ) and
      lifecycleOwner = flowEntry.getArgument(argumentIndex).getUnconverted() and
      free.getEnclosingFunction() = flowEntry.getEnclosingFunction() and
      free.getFile() = flowEntry.getFile() and
      free.getLocation().getStartLine() > flowEntry.getLocation().getStartLine() and
      freeAccess = rcuStripAddressExpr(free.getFreedExpr()) and
      freeAccess.getTarget() = lifecycleRoot and
      freeIdentityPath = "" and freeDisplayPath = "" and
      freedFieldDepth = 0 and
      freeCallDepth = 0 and flowMode = "direct_cfg_free"
    )
  }

class RcuOwnerWrapperFreeSeed extends TRcuOwnerWrapperFreeSeed {
  RcuDirectRegistration registration;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  Variable lifecycleRoot;
  RcuFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freeCallDepth;
  int freedFieldDepth;
  string flowMode;

  RcuOwnerWrapperFreeSeed() {
    this = MkRcuOwnerWrapperFreeSeed(
      registration, flowEntry, lifecycleOwner, lifecycleRoot,
      free, freeIdentityPath, freeDisplayPath,
      freeCallDepth, freedFieldDepth, flowMode
    )
  }

  RcuDirectRegistration getRegistration() { result = registration }
  FunctionCall getFlowEntry() { result = flowEntry }
  Expr getLifecycleOwner() { result = lifecycleOwner }
  Variable getLifecycleRoot() { result = lifecycleRoot }
  RcuFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreeCallDepth() { result = freeCallDepth }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string getFlowMode() { result = flowMode }
  string toString() { result = "rcu-owner-wrapper-free-seed" }
}

bindingset[depth]
string rcuFreedRegionKind(int depth) {
  depth = 0 and result = "whole_rcu_owner"
  or depth > 0 and result = "nested_subtree_of_rcu_owner"
}

class RcuBarrierCall extends FunctionCall {
  RcuBarrierCall() {
    rcuHasName(this.getTarget(), "rcu_barrier") or
    rcuHasName(this.getTarget(), "rcu_barrier_bh") or
    rcuHasName(this.getTarget(), "rcu_barrier_sched") or
    rcuHasName(this.getTarget(), "rcu_barrier_tasks") or
    rcuHasName(this.getTarget(), "rcu_barrier_tasks_rude") or
    rcuHasName(this.getTarget(), "rcu_barrier_tasks_trace") or
    rcuHasName(this.getTarget(), "srcu_barrier") or
    rcuHasName(this.getTarget(), "synchronize_rcu") or
    rcuHasName(this.getTarget(), "synchronize_rcu_expedited") or
    rcuHasName(this.getTarget(), "synchronize_rcu_tasks") or
    rcuHasName(this.getTarget(), "synchronize_rcu_tasks_rude") or
    rcuHasName(this.getTarget(), "synchronize_rcu_tasks_trace") or
    rcuHasName(this.getTarget(), "synchronize_srcu") or
    rcuHasName(this.getTarget(), "synchronize_srcu_expedited")
  }

  string getApiName() { result = this.getTarget().getName() }
  string getStrength() {
    (
      this.getTarget().getName().matches("rcu_barrier%") or
      rcuHasName(this.getTarget(), "srcu_barrier")
    ) and result = "strong"
    or
    this.getTarget().getName().matches("synchronize_%") and result = "weak"
  }

  string getRcuDomain() {
    (
      rcuHasName(this.getTarget(), "rcu_barrier") or
      rcuHasName(this.getTarget(), "rcu_barrier_bh") or
      rcuHasName(this.getTarget(), "rcu_barrier_sched") or
      rcuHasName(this.getTarget(), "synchronize_rcu") or
      rcuHasName(this.getTarget(), "synchronize_rcu_expedited")
    ) and result = "rcu"
    or
    (
      rcuHasName(this.getTarget(), "rcu_barrier_tasks") or
      rcuHasName(this.getTarget(), "synchronize_rcu_tasks")
    ) and result = "rcu_tasks"
    or
    (
      rcuHasName(this.getTarget(), "rcu_barrier_tasks_rude") or
      rcuHasName(this.getTarget(), "synchronize_rcu_tasks_rude")
    ) and result = "rcu_tasks_rude"
    or
    (
      rcuHasName(this.getTarget(), "rcu_barrier_tasks_trace") or
      rcuHasName(this.getTarget(), "synchronize_rcu_tasks_trace")
    ) and result = "rcu_tasks_trace"
    or
    (
      rcuHasName(this.getTarget(), "srcu_barrier") or
      rcuHasName(this.getTarget(), "synchronize_srcu") or
      rcuHasName(this.getTarget(), "synchronize_srcu_expedited")
    ) and result = "srcu"
  }
}

string rcuBarrierSummaryForFree(RcuDeferCall defer, RcuFreeCall free) {
  exists(RcuBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getRcuDomain() = defer.getRcuDomain() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    result = barrier.getStrength() + "_barrier_before_free:" + barrier.getApiName()
  )
  or
  not exists(RcuBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getRcuDomain() = defer.getRcuDomain() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "none_in_free_function_before_free"
}

string rcuProtectionTagForFree(RcuDeferCall defer, RcuFreeCall free) {
  exists(RcuBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getRcuDomain() = defer.getRcuDomain() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(RcuBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getRcuDomain() = defer.getRcuDomain() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and
  exists(RcuBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getRcuDomain() = defer.getRcuDomain() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(RcuBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getRcuDomain() = defer.getRcuDomain() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "no"
}

newtype TRcuConcurrentFreeRow =
  MkRcuConcurrentFreeRow(
    RcuSetupCall setup, RcuDeferCall defer, Field rcuField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner,
    int deferWrapperDepth, string lifecycleBinding,
    FieldAccess matchedUse, string useIdentityPath, string useDisplayPath,
    int callbackCallDepth,
    RcuFreeCall free, string freeDisplayPath,
    int freeCallDepth, int freedFieldDepth, string flowMode
  ) {
    exists(
      RcuDirectRegistrationUse registrationUse,
      RcuDirectRegistration registration,
      string freeIdentityPath
    |
      registration = registrationUse.getRegistration() and
      setup = registration.getSetup() and
      defer = registration.getDefer() and
      rcuField = registration.getRcuField() and
      callback = registration.getCallback() and
      callbackOwner = registration.getCallbackOwner() and
      callbackRecovery = registration.getCallbackRecovery() and
      flowEntry = registration.getDefer() and
      lifecycleOwner = registration.getRegistrationOwner() and
      deferWrapperDepth = 0 and
      lifecycleBinding = "direct_defer_exact_owner" and
      matchedUse = registrationUse.getUse() and
      useIdentityPath = registrationUse.getUseIdentityPath() and
      useDisplayPath = registrationUse.getUseDisplayPath() and
      callbackCallDepth = registrationUse.getCallbackCallDepth() and
      rcuAnyFreeFinding(
        flowEntry, registration.getRegistrationRoot(), rcuField, callback,
        useIdentityPath, free,
        freeIdentityPath, freeDisplayPath,
        freeCallDepth, freedFieldDepth, flowMode
      )
    )
    or
    exists(
      RcuFieldWrapperUse wrapperUse,
      RcuFieldWrapperRegistration registration, Variable lifecycleRoot,
      string freeIdentityPath
    |
      registration = wrapperUse.getRegistration() and
      setup = registration.getSetup() and
      defer = registration.getDefer() and
      rcuField = registration.getRcuField() and
      callback = registration.getCallback() and
      callbackOwner = registration.getCallbackOwner() and
      callbackRecovery = registration.getCallbackRecovery() and
      flowEntry = registration.getFlowEntry() and
      lifecycleOwner = registration.getLifecycleOwner() and
      lifecycleRoot = registration.getLifecycleRoot() and
      deferWrapperDepth = 1 and
      lifecycleBinding = "rcu_field_defer_wrapper_exact_parameter" and
      matchedUse = wrapperUse.getUse() and
      useIdentityPath = wrapperUse.getUseIdentityPath() and
      useDisplayPath = wrapperUse.getUseDisplayPath() and
      callbackCallDepth = wrapperUse.getCallbackCallDepth() and
      rcuWrapperCallerFreeFinding(
        flowEntry, lifecycleRoot, useIdentityPath, free,
        freeIdentityPath, freeDisplayPath,
        freeCallDepth, freedFieldDepth, flowMode
      )
    )
  }

class RcuConcurrentFreeRow extends TRcuConcurrentFreeRow {
  RcuSetupCall setup;
  RcuDeferCall defer;
  Field rcuField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  int deferWrapperDepth;
  string lifecycleBinding;
  FieldAccess matchedUse;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;
  RcuFreeCall free;
  string freeDisplayPath;
  int freeCallDepth;
  int freedFieldDepth;
  string flowMode;

  RcuConcurrentFreeRow() {
    this = MkRcuConcurrentFreeRow(
      setup, defer, rcuField,
      callback, callbackOwner, callbackRecovery,
      flowEntry, lifecycleOwner,
      deferWrapperDepth, lifecycleBinding,
      matchedUse, useIdentityPath, useDisplayPath, callbackCallDepth,
      free, freeDisplayPath, freeCallDepth, freedFieldDepth, flowMode
    )
  }

  pragma[noinline] string getLifecycleFile() { result = flowEntry.getFile().getRelativePath() }
  pragma[noinline] int getLifecycleLine() { result = flowEntry.getLocation().getStartLine() }
  pragma[noinline] string getLifecycleFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getLifecycleApi() { result = defer.getDeferKind() }
  pragma[noinline] string getLifecycleArgument() { result = flowEntry.toString() }
  pragma[noinline] string getLifecycleBinding() { result = lifecycleBinding }
  pragma[noinline] int getDeferWrapperDepth() { result = deferWrapperDepth }

  pragma[noinline] string getSetupFile() { result = setup.getFile().getRelativePath() }
  pragma[noinline] int getSetupLine() { result = setup.getLocation().getStartLine() }
  pragma[noinline] string getSetupFunction() { result = setup.getEnclosingFunction().getName() }
  pragma[noinline] string getSetupApi() { result = setup.getTarget().getName() }
  pragma[noinline] string getSetupBinding() { result = rcuField.getName() }

  pragma[noinline] string getCallbackName() { result = callback.getName() }
  pragma[noinline] string getCallbackFile() { result = callback.getFile().getRelativePath() }
  pragma[noinline] int getCallbackLine() { result = callback.getLocation().getStartLine() }
  pragma[noinline] string getCallbackRecovery() { result = callbackRecovery }
  pragma[noinline] string getCallbackKind() { result = setup.getSetupKind() }
  pragma[noinline] int getCallbackCallDepth() { result = callbackCallDepth }

  pragma[noinline] string getHolderFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getHolderRoot() { result = lifecycleOwner.toString() }
  pragma[noinline] string getHolderType() { result = rcuField.getDeclaringType().toString() }
  pragma[noinline] string getRcuFieldName() { result = rcuField.getName() }

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
    result = rcuFreedRegionKind(freedFieldDepth) + ";" + flowMode
  }

  pragma[noinline] string getUseFile() { result = matchedUse.getFile().getRelativePath() }
  pragma[noinline] int getUseLine() { result = matchedUse.getLocation().getStartLine() }
  pragma[noinline] string getUseFunction() { result = matchedUse.getEnclosingFunction().getName() }
  pragma[noinline] string getUseExpression() { result = matchedUse.toString() }
  pragma[noinline] string getUsedObjectPath() {
    useDisplayPath = "" and result = "<owner>"
    or useDisplayPath != "" and result = useDisplayPath
  }
  pragma[noinline] string getBarrierContext() { result = rcuBarrierSummaryForFree(defer, free) }
  pragma[noinline] string getProtectionTag() { result = rcuProtectionTagForFree(defer, free) }

  string toString() { result = "rcu-concurrent-free-row" }
}
