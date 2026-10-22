import KernelObjectPathFlow
/**
 * Lightweight Linux NAPI lifecycle/free versus poll-callback/use model.
 *
 * The query is intentionally bounded: owner paths contain at most three
 * declared fields and setup/schedule, callback-use, and free wrappers contain
 * at most one direct call edge.  This keeps the analysis relational and avoids
 * whole-program global data flow while preserving the same object-tree
 * semantics as the finalized timer/workqueue queries.
 */

import cpp

predicate napiHasName(Function f, string name) {
  f.getName() = name or f.hasGlobalName(name)
}

int napiMaxTreeFieldDepth() { result = 5 }
int napiMaxWrapperDepth() { result = 3 }

class NapiSetupCall extends FunctionCall {
  NapiSetupCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        napiHasName(f, "netif_napi_add") or
        napiHasName(f, "netif_napi_add_locked") or
        napiHasName(f, "netif_napi_add_weight") or
        napiHasName(f, "netif_napi_add_weight_locked") or
        napiHasName(f, "netif_napi_add_tx") or
        napiHasName(f, "netif_napi_add_tx_weight") or
        napiHasName(f, "netif_napi_add_config") or
        napiHasName(f, "netif_napi_add_config_locked") or
        napiHasName(f, "_netif_napi_add") or
        napiHasName(f, "__netif_napi_add") or
        napiHasName(f, "netif_napi_add_mq")
      ) and
      this.getNumberOfArguments() > 2
    )
  }

  Expr getNapiArg() { result = this.getArgument(1) }
  Expr getCallbackArg() { result = this.getArgument(2) }

  Function getCallbackFunction() {
    exists(FunctionAccess access |
      access = this.getCallbackArg().getUnconverted() and
      result = access.getTarget()
    )
    or
    exists(AddressOfExpr address, FunctionAccess access |
      address = this.getCallbackArg().getUnconverted() and
      access = address.getOperand().getUnconverted() and
      result = access.getTarget()
    )
  }
}

class NapiScheduleCall extends FunctionCall {
  NapiScheduleCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        napiHasName(f, "napi_schedule") or
        napiHasName(f, "napi_schedule_irqoff") or
        napiHasName(f, "__napi_schedule") or
        napiHasName(f, "__napi_schedule_irqoff") or
        napiHasName(f, "napi_reschedule")
      ) and
      this.getNumberOfArguments() > 0
    )
  }

  Expr getNapiArg() { result = this.getArgument(0) }
  string getScheduleKind() { result = this.getTarget().getName() }
}

predicate immediateNapiFreeArgument(Function target, int argumentIndex, string freeKind) {
  napiHasName(target, "kfree") and argumentIndex = 0 and freeKind = "heap"
  or napiHasName(target, "kfree_sensitive") and argumentIndex = 0 and freeKind = "heap_sensitive"
  or napiHasName(target, "kfree_const") and argumentIndex = 0 and freeKind = "heap_or_const"
  or napiHasName(target, "kzfree") and argumentIndex = 0 and freeKind = "heap_zeroed"
  or napiHasName(target, "kvfree") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc"
  or napiHasName(target, "kvfree_sensitive") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc_sensitive"
  or napiHasName(target, "vfree") and argumentIndex = 0 and freeKind = "vmalloc"
  or napiHasName(target, "vfree_atomic") and argumentIndex = 0 and freeKind = "vmalloc_atomic"
  or napiHasName(target, "devm_kfree") and argumentIndex = 1 and freeKind = "device_managed_heap"
  or napiHasName(target, "kmem_cache_free") and argumentIndex = 1 and freeKind = "slab_cache"
  or napiHasName(target, "mempool_free") and argumentIndex = 0 and freeKind = "mempool"
  or napiHasName(target, "free_percpu") and argumentIndex = 0 and freeKind = "percpu"
  or napiHasName(target, "dma_free_coherent") and argumentIndex = 2 and freeKind = "dma_coherent"
  or napiHasName(target, "dma_free_attrs") and argumentIndex = 2 and freeKind = "dma_attrs"
  or napiHasName(target, "dma_free_noncoherent") and argumentIndex = 2 and freeKind = "dma_noncoherent"
  or napiHasName(target, "dmam_free_coherent") and argumentIndex = 2 and freeKind = "device_managed_dma"
  or napiHasName(target, "dma_pool_free") and argumentIndex = 1 and freeKind = "dma_pool"
  or napiHasName(target, "pci_free_consistent") and argumentIndex = 2 and freeKind = "pci_consistent"
  or napiHasName(target, "pci_pool_free") and argumentIndex = 1 and freeKind = "pci_pool"
  or napiHasName(target, "usb_free_coherent") and argumentIndex = 2 and freeKind = "usb_coherent"
  or napiHasName(target, "gen_pool_free") and argumentIndex = 1 and freeKind = "generic_pool"
  or napiHasName(target, "free_pages") and argumentIndex = 0 and freeKind = "pages"
  or napiHasName(target, "free_pages_exact") and argumentIndex = 0 and freeKind = "pages_exact"
  or napiHasName(target, "__free_pages") and argumentIndex = 0 and freeKind = "pages_internal"
  or napiHasName(target, "__free_page") and argumentIndex = 0 and freeKind = "page_internal"
  or napiHasName(target, "free_page") and argumentIndex = 0 and freeKind = "page"
  or napiHasName(target, "page_frag_free") and argumentIndex = 0 and freeKind = "page_frag"
  or napiHasName(target, "free_netdev") and argumentIndex = 0 and freeKind = "netdev"
  or napiHasName(target, "hci_free_dev") and argumentIndex = 0 and freeKind = "hci_dev"
  or napiHasName(target, "usb_free_urb") and argumentIndex = 0 and freeKind = "usb_urb"
  or napiHasName(target, "kfree_skb") and argumentIndex = 0 and freeKind = "skb"
  or napiHasName(target, "dev_kfree_skb_any") and argumentIndex = 0 and freeKind = "skb"
  or napiHasName(target, "consume_skb") and argumentIndex = 0 and freeKind = "skb"
  or napiHasName(target, "kmem_cache_free_bulk") and argumentIndex = 2 and freeKind = "slab_cache_bulk"
  or napiHasName(target, "kfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_heap"
  or napiHasName(target, "kvfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_vm"
}

class NapiFreeCall extends FunctionCall {
  NapiFreeCall() {
    exists(int argumentIndex, string freeKind |
      immediateNapiFreeArgument(this.getTarget(), argumentIndex, freeKind) and
      argumentIndex < this.getNumberOfArguments()
    )
  }

  int getFreedArgumentIndex() { immediateNapiFreeArgument(this.getTarget(), result, _) }
  Expr getFreedExpr() { result = this.getArgument(this.getFreedArgumentIndex()) }
  string getFreeKind() { immediateNapiFreeArgument(this.getTarget(), _, result) }
  string getFreeApi() { result = this.getTarget().getName() }
}

bindingset[before]
predicate napiCfgStrictlyAfter(ControlFlowNode before, ControlFlowNode after) {
  before.getControlFlowScope() = after.getControlFlowScope() and
  before.getASuccessor+() = after
}

predicate napiOwnerAndField(Expr napiArg, Expr owner, Field napiField) {
  exists(FieldAccess access |
    (
      access = napiArg.getUnconverted()
      or exists(AddressOfExpr address |
        address = napiArg.getUnconverted() and
        access = address.getOperand().getUnconverted()
      )
    ) and
    owner = access.getQualifier().getUnconverted() and
    napiField = access.getTarget() and
    napiField.getType().getUnspecifiedType().hasName("napi_struct")
  )
}

string napiFieldIdentity(Field field) {
  result = field.getFile().getRelativePath() + ":" +
    field.getLocation().getStartLine().toString() + ":" +
    field.getLocation().getStartColumn().toString()
}

Expr napiStripAddressExpr(Expr expression) {
  not expression.getUnconverted() instanceof AddressOfExpr and
  result = expression.getUnconverted()
  or
  exists(AddressOfExpr address |
    address = expression.getUnconverted() and
    result = address.getOperand().getUnconverted()
  )
}

bindingset[expression]
predicate napiExprRootAndPath(
  Expr expression, Variable root,
  string identityPath, string displayPath, int depth
) {
  depth = 0 and
  exists(VariableAccess access |
    access = napiStripAddressExpr(expression) and root = access.getTarget()
  ) and
  identityPath = "" and displayPath = ""
  or
  depth = 1 and napiMaxTreeFieldDepth() >= 1 and
  exists(FieldAccess f1, VariableAccess access |
    f1 = napiStripAddressExpr(expression) and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = napiFieldIdentity(f1.getTarget()) and
    displayPath = f1.getTarget().getName()
  )
  or
  depth = 2 and napiMaxTreeFieldDepth() >= 2 and
  exists(FieldAccess f1, FieldAccess f2, VariableAccess access |
    f2 = napiStripAddressExpr(expression) and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = napiFieldIdentity(f1.getTarget()) + "/" + napiFieldIdentity(f2.getTarget()) and
    displayPath = f1.getTarget().getName() + "." + f2.getTarget().getName()
  )
  or
  depth = 3 and napiMaxTreeFieldDepth() >= 3 and
  exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, VariableAccess access |
    f3 = napiStripAddressExpr(expression) and
    f2 = f3.getQualifier().getUnconverted() and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = napiFieldIdentity(f1.getTarget()) + "/" +
      napiFieldIdentity(f2.getTarget()) + "/" + napiFieldIdentity(f3.getTarget()) and
    displayPath = f1.getTarget().getName() + "." +
      f2.getTarget().getName() + "." + f3.getTarget().getName()
  )
}

predicate napiVariablePointsToType(Variable variable, Type targetType) {
  exists(PointerType pointer |
    pointer = variable.getType().getUnspecifiedType() and
    pointer.getBaseType().getUnspecifiedType() = targetType.getUnspecifiedType()
  )
}

bindingset[leftIdentity, rightIdentity]
string napiJoinIdentityPath(string leftIdentity, string rightIdentity) {
  leftIdentity = "" and result = rightIdentity
  or rightIdentity = "" and result = leftIdentity
  or leftIdentity != "" and rightIdentity != "" and
    result = leftIdentity + "/" + rightIdentity
}

bindingset[leftDisplay, rightDisplay]
string napiJoinDisplayPath(string leftDisplay, string rightDisplay) {
  leftDisplay = "" and result = rightDisplay
  or rightDisplay = "" and result = leftDisplay
  or leftDisplay != "" and rightDisplay != "" and
    result = leftDisplay + "." + rightDisplay
}

bindingset[prefix, full]
predicate napiPathPrefix(string prefix, string full) {
  prefix = "" or prefix = full or full.indexOf(prefix + "/") = 0
}

predicate napiTerminalRealFieldUse(FieldAccess use) {
  not exists(AddressOfExpr address |
    address.getOperand().getUnconverted() = use.getUnconverted()
  ) and
  not exists(FieldAccess outer |
    outer.getQualifier().getUnconverted() = use.getUnconverted()
  ) and
  (use.isRValue() or use.isModified() or use.isUsedAsLValue())
}

/** The declared NAPI field and registered poll callback are exact. */
predicate napiSetupMatchesField(
  NapiSetupCall setup, Field napiField, Function callback
) {
  exists(Expr setupOwner |
    napiOwnerAndField(setup.getNapiArg(), setupOwner, napiField) and
    callback = setup.getCallbackFunction()
  )
}

/** Direct napi_schedule*(&owner->napi). */
pragma[noinline]
predicate napiDirectLifecycleAnchor(
  NapiSetupCall setup, NapiScheduleCall schedule, Field napiField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(string identityPath, string displayPath, int depth |
    napiSetupMatchesField(setup, napiField, callback) and
    napiOwnerAndField(schedule.getNapiArg(), lifecycleOwner, napiField) and
    napiExprRootAndPath(
      lifecycleOwner, lifecycleRoot, identityPath, displayPath, depth
    ) and identityPath = "" and
    napiVariablePointsToType(lifecycleRoot, napiField.getDeclaringType()) and
    flowEntry = schedule
  )
}

/** Caller passes owner to a one-hop wrapper that performs napi_schedule*. */
pragma[noinline]
predicate napiOwnerScheduleWrapperLifecycleAnchor(
  NapiSetupCall setup, NapiScheduleCall schedule, Field napiField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(
    Expr scheduleOwner, Variable scheduleRoot,
    string scheduleIdentity, string scheduleDisplay, int scheduleDepth,
    FunctionCall wrapper, int argumentIndex,
    Variable callerRoot, string argumentIdentity, string argumentDisplay,
    int argumentDepth, Parameter calleeRoot
  |
    napiMaxWrapperDepth() >= 3 and
    napiSetupMatchesField(setup, napiField, callback) and
    napiOwnerAndField(schedule.getNapiArg(), scheduleOwner, napiField) and
    napiExprRootAndPath(
      scheduleOwner, scheduleRoot, scheduleIdentity, scheduleDisplay, scheduleDepth
    ) and scheduleIdentity = "" and
    calleeRoot = scheduleRoot and
    wrapper.getTarget() = schedule.getEnclosingFunction() and
    calleeRoot = wrapper.getTarget().getParameter(argumentIndex) and
    napiExprRootAndPath(
      wrapper.getArgument(argumentIndex), callerRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and argumentIdentity = "" and
    napiVariablePointsToType(callerRoot, napiField.getDeclaringType()) and
    lifecycleOwner = wrapper.getArgument(argumentIndex).getUnconverted() and
    lifecycleRoot = callerRoot and flowEntry = wrapper
  )
}

/** Caller passes &owner->napi to a one-hop wrapper taking napi_struct *. */
pragma[noinline]
predicate napiFieldScheduleWrapperLifecycleAnchor(
  NapiSetupCall setup, NapiScheduleCall schedule, Field napiField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(
    FunctionCall wrapper, int argumentIndex, Parameter calleeNapi,
    VariableAccess scheduleParameter,
    string ownerIdentity, string ownerDisplay, int ownerDepth
  |
    napiMaxWrapperDepth() >= 3 and
    napiSetupMatchesField(setup, napiField, callback) and
    wrapper.getTarget() = schedule.getEnclosingFunction() and
    calleeNapi = wrapper.getTarget().getParameter(argumentIndex) and
    scheduleParameter = schedule.getNapiArg().getUnconverted() and
    scheduleParameter.getTarget() = calleeNapi and
    napiOwnerAndField(wrapper.getArgument(argumentIndex), lifecycleOwner, napiField) and
    napiExprRootAndPath(
      lifecycleOwner, lifecycleRoot, ownerIdentity, ownerDisplay, ownerDepth
    ) and ownerIdentity = "" and
    napiVariablePointsToType(lifecycleRoot, napiField.getDeclaringType()) and
    flowEntry = wrapper
  )
}

pragma[noinline]
predicate napiAnyLifecycleAnchor(
  NapiSetupCall setup, NapiScheduleCall schedule, Field napiField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry, int scheduleWrapperDepth, string lifecycleBinding
) {
  napiDirectLifecycleAnchor(
    setup, schedule, napiField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and scheduleWrapperDepth = 0 and lifecycleBinding = "direct_schedule_exact_owner"
  or
  napiOwnerScheduleWrapperLifecycleAnchor(
    setup, schedule, napiField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and scheduleWrapperDepth = 1 and lifecycleBinding = "owner_schedule_wrapper_exact_parameter"
  or
  napiFieldScheduleWrapperLifecycleAnchor(
    setup, schedule, napiField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and scheduleWrapperDepth = 1 and lifecycleBinding = "napi_field_schedule_wrapper_exact_parameter"
}

/** container_of(napi, owner_type, exact_napi_field). */
predicate napiContainerOfCallbackOwner(
  Function callback, Field napiField, Variable callbackOwner
) {
  exists(MacroInvocation recover, LocalVariable local, Initializer initializer |
    recover.getEnclosingFunction() = callback and
    recover.getMacroName() = "container_of" and
    recover.getUnexpandedArgument(2) = napiField.getName() and
    local = callbackOwner and local.getFunction() = callback and
    initializer = local.getInitializer() and (initializer.getExpr() = recover.getExpr() or kernelLocalValueFlow(recover.getExpr(), local.getAnAccess())) and
    napiVariablePointsToType(local, napiField.getDeclaringType())
  )
}

predicate napiCallbackParameter(Function callback, Expr expression) {
  exists(VariableAccess access, Parameter parameter, PointerType pointer |
    access = expression.getUnconverted() and parameter = access.getTarget() and
    parameter.getFunction() = callback and
    pointer = parameter.getType().getUnspecifiedType() and
    pointer.getBaseType().getUnspecifiedType().hasName("napi_struct")
  )
}

predicate netdevFromNapiCallbackParameter(Function callback, Expr expression) {
  exists(FieldAccess dev |
    dev = expression.getUnconverted() and dev.getTarget().getName() = "dev" and
    napiCallbackParameter(callback, dev.getQualifier())
  )
  or
  exists(FunctionCall toNetdev |
    toNetdev = expression.getUnconverted() and
    napiHasName(toNetdev.getTarget(), "napi_to_net_dev") and
    toNetdev.getNumberOfArguments() > 0 and
    napiCallbackParameter(callback, toNetdev.getArgument(0))
  )
}

/** Common owner recovery through netdev_priv(napi->dev/napi_to_net_dev(napi)). */
predicate napiNetdevPrivCallbackOwner(
  Function callback, Field napiField, Variable callbackOwner
) {
  exists(LocalVariable local, Initializer initializer, FunctionCall netdevPriv |
    local = callbackOwner and local.getFunction() = callback and
    initializer = local.getInitializer() and
    netdevPriv = initializer.getExpr().getUnconverted() and
    napiHasName(netdevPriv.getTarget(), "netdev_priv") and
    netdevPriv.getNumberOfArguments() > 0 and
    netdevFromNapiCallbackParameter(callback, netdevPriv.getArgument(0)) and
    napiVariablePointsToType(local, napiField.getDeclaringType())
  )
}

predicate napiCallbackOwnerSeed(
  Function callback, Field napiField, Variable callbackOwner, string recoveryKind
) {
  napiContainerOfCallbackOwner(callback, napiField, callbackOwner) and
  recoveryKind = "container_of_exact_napi_field"
  or
  napiNetdevPrivCallbackOwner(callback, napiField, callbackOwner) and
  recoveryKind = "netdev_priv_from_napi_parameter"
}

Function napiVariableFunction(Variable variable) {
  exists(Parameter parameter |
    variable = parameter and result = parameter.getFunction()
  )
  or
  exists(LocalVariable local |
    variable = local and result = local.getFunction()
  )
}

pragma[noinline]
predicate napiDirectCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(int useDepth |
    use.getEnclosingFunction() = napiVariableFunction(callbackOwner) and
    napiTerminalRealFieldUse(use) and
    napiExprRootAndPath(
      use, callbackOwner, useIdentityPath, useDisplayPath, useDepth
    )
  )
}

pragma[noinline]
predicate napiOneHopCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    napiMaxWrapperDepth() >= 3 and
    helperCall.getEnclosingFunction() = napiVariableFunction(callbackOwner) and
    napiExprRootAndPath(
      helperCall.getArgument(argumentIndex), callbackOwner,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    use.getEnclosingFunction() = helperRoot.getFunction() and
    napiTerminalRealFieldUse(use) and
    napiExprRootAndPath(
      use, helperRoot, helperIdentity, helperDisplay, helperDepth
    ) and
    useIdentityPath = napiJoinIdentityPath(argumentIdentity, helperIdentity) and
    useDisplayPath = napiJoinDisplayPath(argumentDisplay, helperDisplay)
  )
}

pragma[noinline]
predicate napiTwoHopCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(FunctionCall firstCall, FunctionCall secondCall,
    int firstIndex, int secondIndex,
    string firstIdentity, string firstDisplay, int firstDepth,
    string secondIdentity, string secondDisplay, int secondDepth, int useDepth,
    Parameter firstRoot, Parameter secondRoot |
    napiMaxWrapperDepth() >= 3 and
    firstCall.getEnclosingFunction() = napiVariableFunction(callbackOwner) and
    napiExprRootAndPath(firstCall.getArgument(firstIndex), callbackOwner,
      firstIdentity, firstDisplay, firstDepth) and
    firstRoot = firstCall.getTarget().getParameter(firstIndex) and
    secondCall.getEnclosingFunction() = firstRoot.getFunction() and
    napiExprRootAndPath(secondCall.getArgument(secondIndex), firstRoot,
      secondIdentity, secondDisplay, secondDepth) and
    secondRoot = secondCall.getTarget().getParameter(secondIndex) and
    use.getEnclosingFunction() = secondRoot.getFunction() and
    napiTerminalRealFieldUse(use) and
    napiExprRootAndPath(use, secondRoot, useIdentityPath, useDisplayPath, useDepth)
  )
}
predicate napiAnyCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath, int callbackCallDepth
) {
  napiDirectCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 0
  or
  napiOneHopCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 1
  or
  napiTwoHopCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 2
}

predicate napiTeardownLikeFunction(Function function) {
  function.getName().matches("%remove%") or function.getName().matches("%detach%") or
  function.getName().matches("%cleanup%") or function.getName().matches("%destroy%") or
  function.getName().matches("%release%") or function.getName().matches("%shutdown%") or
  function.getName().matches("%unregister%") or function.getName().matches("%deinit%") or
  function.getName().matches("%exit%") or function.getName().matches("%stop%") or
  function.getName().matches("%close%") or function.getName().matches("free_%") or
  function.getName().matches("%_free")
}

pragma[noinline]
predicate napiCallerDirectFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  Variable callbackOwner, FieldAccess callbackUse,
  string callbackUseIdentityPath, string callbackUseDisplayPath,
  int callbackCallDepth, NapiFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  napiAnyCallbackRealUse(
    callbackOwner, callbackUse,
    callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth
  ) and
  napiCfgStrictlyAfter(flowEntry, free) and
  napiExprRootAndPath(
    free.getFreedExpr(), lifecycleRoot,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and
  napiPathPrefix(freeIdentityPath, callbackUseIdentityPath)
}

pragma[noinline]
predicate napiCallerOneHopFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  Variable callbackOwner, FieldAccess callbackUse,
  string callbackUseIdentityPath, string callbackUseDisplayPath,
  int callbackCallDepth, NapiFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    napiMaxWrapperDepth() >= 3 and
    napiAnyCallbackRealUse(
      callbackOwner, callbackUse,
      callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth
    ) and
    napiCfgStrictlyAfter(flowEntry, helperCall) and not helperCall instanceof NapiFreeCall and
    napiExprRootAndPath(
      helperCall.getArgument(argumentIndex), lifecycleRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    free.getEnclosingFunction() = helperRoot.getFunction() and
    napiExprRootAndPath(
      free.getFreedExpr(), helperRoot,
      helperIdentity, helperDisplay, helperDepth
    ) and
    freeIdentityPath = napiJoinIdentityPath(argumentIdentity, helperIdentity) and
    freeDisplayPath = napiJoinDisplayPath(argumentDisplay, helperDisplay) and
    freedFieldDepth = argumentDepth + helperDepth and
    napiPathPrefix(freeIdentityPath, callbackUseIdentityPath)
  )
}

pragma[noinline]
predicate napiCrossLifecycleDirectFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field napiField, Function callback,
  Variable callbackOwner, FieldAccess callbackUse,
  string callbackUseIdentityPath, string callbackUseDisplayPath,
  int callbackCallDepth, NapiFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(Variable freeRoot |
    napiAnyCallbackRealUse(
      callbackOwner, callbackUse,
      callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth
    ) and
    free.getEnclosingFunction() != flowEntry.getEnclosingFunction() and
    free.getEnclosingFunction() != callback and
    napiTeardownLikeFunction(free.getEnclosingFunction()) and
    napiExprRootAndPath(
      free.getFreedExpr(), freeRoot,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    ) and
    freeRoot.getType().getUnspecifiedType() = lifecycleRoot.getType().getUnspecifiedType() and
    napiVariablePointsToType(freeRoot, napiField.getDeclaringType()) and
    napiPathPrefix(freeIdentityPath, callbackUseIdentityPath)
  )
}

pragma[noinline]
predicate napiCrossLifecycleOneHopFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field napiField, Function callback,
  Variable callbackOwner, FieldAccess callbackUse,
  string callbackUseIdentityPath, string callbackUseDisplayPath,
  int callbackCallDepth, NapiFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(
    Function teardown, FunctionCall helperCall, int argumentIndex,
    Variable teardownRoot, string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    napiMaxWrapperDepth() >= 3 and
    napiAnyCallbackRealUse(
      callbackOwner, callbackUse,
      callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth
    ) and
    teardown = helperCall.getEnclosingFunction() and
    teardown != flowEntry.getEnclosingFunction() and teardown != callback and
    napiTeardownLikeFunction(teardown) and
    napiExprRootAndPath(
      helperCall.getArgument(argumentIndex), teardownRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    teardownRoot.getType().getUnspecifiedType() = lifecycleRoot.getType().getUnspecifiedType() and
    napiVariablePointsToType(teardownRoot, napiField.getDeclaringType()) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    free.getEnclosingFunction() = helperRoot.getFunction() and
    napiExprRootAndPath(
      free.getFreedExpr(), helperRoot,
      helperIdentity, helperDisplay, helperDepth
    ) and
    freeIdentityPath = napiJoinIdentityPath(argumentIdentity, helperIdentity) and
    freeDisplayPath = napiJoinDisplayPath(argumentDisplay, helperDisplay) and
    freedFieldDepth = argumentDepth + helperDepth and
    napiPathPrefix(freeIdentityPath, callbackUseIdentityPath)
  )
}

pragma[noinline]
predicate napiAnyFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field napiField, Function callback,
  Variable callbackOwner, FieldAccess callbackUse,
  string callbackUseIdentityPath, string callbackUseDisplayPath,
  int callbackCallDepth, NapiFreeCall free,
  string freeIdentityPath, string freeDisplayPath,
  int freeCallDepth, int freedFieldDepth, string flowMode
) {
  napiCallerDirectFreeFinding(
    flowEntry, lifecycleRoot, callbackOwner, callbackUse,
    callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "direct_cfg_free"
  or
  napiCallerOneHopFreeFinding(
    flowEntry, lifecycleRoot, callbackOwner, callbackUse,
    callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "caller_one_hop_free"
  or
  napiCrossLifecycleDirectFreeFinding(
    flowEntry, lifecycleRoot, napiField, callback,
    callbackOwner, callbackUse,
    callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "cross_lifecycle_teardown_root"
  or
  napiCrossLifecycleOneHopFreeFinding(
    flowEntry, lifecycleRoot, napiField, callback,
    callbackOwner, callbackUse,
    callbackUseIdentityPath, callbackUseDisplayPath, callbackCallDepth, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "cross_lifecycle_one_hop_free"
}

bindingset[depth]
string napiFreedRegionKind(int depth) {
  depth = 0 and result = "whole_napi_owner"
  or depth > 0 and result = "nested_subtree_of_napi_owner"
}

class NapiBarrierCall extends FunctionCall {
  NapiBarrierCall() {
    napiHasName(this.getTarget(), "napi_disable") or
    napiHasName(this.getTarget(), "napi_disable_locked") or
    napiHasName(this.getTarget(), "napi_synchronize") or
    napiHasName(this.getTarget(), "napi_synchronize_irqoff") or
    napiHasName(this.getTarget(), "netif_napi_del") or
    napiHasName(this.getTarget(), "netif_napi_del_locked")
  }

  string getApiName() { result = this.getTarget().getName() }
  string getStrength() {
    (
      napiHasName(this.getTarget(), "napi_disable") or
      napiHasName(this.getTarget(), "napi_disable_locked")
    ) and result = "strong"
    or
    (
      napiHasName(this.getTarget(), "napi_synchronize") or
      napiHasName(this.getTarget(), "napi_synchronize_irqoff") or
      napiHasName(this.getTarget(), "netif_napi_del") or
      napiHasName(this.getTarget(), "netif_napi_del_locked")
    ) and result = "weak"
  }
}

string napiBarrierSummaryForFree(NapiFreeCall free) {
  exists(NapiBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    result = barrier.getStrength() + "_barrier_before_free:" + barrier.getApiName()
  )
  or
  not exists(NapiBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "none_in_free_function_before_free"
}

string napiProtectionTagForFree(NapiFreeCall free) {
  exists(NapiBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(NapiBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and
  exists(NapiBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(NapiBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "no"
}

newtype TNapiConcurrentFreeRow =
  MkNapiConcurrentFreeRow(
    NapiSetupCall setup, NapiScheduleCall schedule, Field napiField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner,
    int scheduleWrapperDepth, string lifecycleBinding,
    FieldAccess matchedUse, string useIdentityPath, string useDisplayPath,
    int callbackCallDepth,
    NapiFreeCall free, string freeDisplayPath,
    int freeCallDepth, int freedFieldDepth, string flowMode
  ) {
    exists(Variable lifecycleRoot, string freeIdentityPath |
      napiAnyLifecycleAnchor(
        setup, schedule, napiField, callback, lifecycleOwner, lifecycleRoot,
        flowEntry, scheduleWrapperDepth, lifecycleBinding
      ) and
      napiCallbackOwnerSeed(
        callback, napiField, callbackOwner, callbackRecovery
      ) and
      napiAnyFreeFinding(
        flowEntry, lifecycleRoot, napiField, callback,
        callbackOwner, matchedUse,
        useIdentityPath, useDisplayPath, callbackCallDepth, free,
        freeIdentityPath, freeDisplayPath,
        freeCallDepth, freedFieldDepth, flowMode
      )
    )
  }

class NapiConcurrentFreeRow extends TNapiConcurrentFreeRow {
  NapiSetupCall setup;
  NapiScheduleCall schedule;
  Field napiField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  int scheduleWrapperDepth;
  string lifecycleBinding;
  FieldAccess matchedUse;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;
  NapiFreeCall free;
  string freeDisplayPath;
  int freeCallDepth;
  int freedFieldDepth;
  string flowMode;

  NapiConcurrentFreeRow() {
    this = MkNapiConcurrentFreeRow(
      setup, schedule, napiField,
      callback, callbackOwner, callbackRecovery,
      flowEntry, lifecycleOwner,
      scheduleWrapperDepth, lifecycleBinding,
      matchedUse, useIdentityPath, useDisplayPath, callbackCallDepth,
      free, freeDisplayPath, freeCallDepth, freedFieldDepth, flowMode
    )
  }

  pragma[noinline] string getLifecycleFile() { result = flowEntry.getFile().getRelativePath() }
  pragma[noinline] int getLifecycleLine() { result = flowEntry.getLocation().getStartLine() }
  pragma[noinline] string getLifecycleFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getLifecycleApi() { result = schedule.getScheduleKind() }
  pragma[noinline] string getLifecycleArgument() { result = flowEntry.toString() }
  pragma[noinline] string getLifecycleBinding() { result = lifecycleBinding }
  pragma[noinline] int getScheduleWrapperDepth() { result = scheduleWrapperDepth }

  pragma[noinline] string getSetupFile() { result = setup.getFile().getRelativePath() }
  pragma[noinline] int getSetupLine() { result = setup.getLocation().getStartLine() }
  pragma[noinline] string getSetupFunction() { result = setup.getEnclosingFunction().getName() }
  pragma[noinline] string getSetupApi() { result = setup.getTarget().getName() }
  pragma[noinline] string getSetupBinding() { result = napiField.getName() }

  pragma[noinline] string getCallbackName() { result = callback.getName() }
  pragma[noinline] string getCallbackFile() { result = callback.getFile().getRelativePath() }
  pragma[noinline] int getCallbackLine() { result = callback.getLocation().getStartLine() }
  pragma[noinline] string getCallbackRecovery() { result = callbackRecovery }
  pragma[noinline] int getCallbackCallDepth() { result = callbackCallDepth }

  pragma[noinline] string getHolderFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getHolderRoot() { result = lifecycleOwner.toString() }
  pragma[noinline] string getHolderType() { result = napiField.getDeclaringType().toString() }
  pragma[noinline] string getNapiFieldName() { result = napiField.getName() }

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
    result = napiFreedRegionKind(freedFieldDepth) + ";" + flowMode
  }

  pragma[noinline] string getUseFile() { result = matchedUse.getFile().getRelativePath() }
  pragma[noinline] int getUseLine() { result = matchedUse.getLocation().getStartLine() }
  pragma[noinline] string getUseFunction() { result = matchedUse.getEnclosingFunction().getName() }
  pragma[noinline] string getUseExpression() { result = matchedUse.toString() }
  pragma[noinline] string getUsedObjectPath() {
    useDisplayPath = "" and result = "<owner>"
    or useDisplayPath != "" and result = useDisplayPath
  }
  pragma[noinline] string getBarrierContext() { result = napiBarrierSummaryForFree(free) }
  pragma[noinline] string getProtectionTag() { result = napiProtectionTagForFree(free) }

  string toString() { result = "napi-concurrent-free-row" }
}
