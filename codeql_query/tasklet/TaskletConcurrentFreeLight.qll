import KernelObjectPathFlow
/**
 * Lightweight Linux tasklet lifecycle/free versus callback/use model.
 *
 * The query is intentionally bounded: owner paths contain at most three
 * declared fields and setup/schedule, callback-use, and free wrappers contain
 * at most one direct call edge.  This keeps the analysis relational and avoids
 * whole-program global data flow while preserving the same object-tree
 * semantics as the finalized timer/workqueue queries.
 */

import cpp

predicate taskletHasName(Function f, string name) {
  f.hasName(name)
}

int taskletMaxTreeFieldDepth() { result = 5 }
int taskletMaxWrapperDepth() { result = 3 }

class TaskletSetupCall extends FunctionCall {
  TaskletSetupCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        taskletHasName(f, "tasklet_setup") or
        taskletHasName(f, "tasklet_setup_on_stack") or
        taskletHasName(f, "tasklet_init") or
        taskletHasName(f, "tasklet_init_on_stack")
      ) and
      this.getNumberOfArguments() > 1
    )
  }

  Expr getTaskletArg() { result = this.getArgument(0) }
  Expr getCallbackArg() { result = this.getArgument(1) }
  Expr getDataArg() {
    this.getNumberOfArguments() > 2 and result = this.getArgument(2)
  }

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

  string getSetupKind() {
    exists(Function callback, PointerType pointer |
      callback = this.getCallbackFunction() and
      pointer = callback.getParameter(0).getType().getUnspecifiedType() and
      pointer.getBaseType().getUnspecifiedType().hasName("tasklet_struct") and
      result = "tasklet_struct_callback"
    )
    or
    not exists(Function callback, PointerType pointer |
      callback = this.getCallbackFunction() and
      pointer = callback.getParameter(0).getType().getUnspecifiedType() and
      pointer.getBaseType().getUnspecifiedType().hasName("tasklet_struct")
    ) and result = "tasklet_old_ulong_callback"
  }
}

class TaskletScheduleCall extends FunctionCall {
  TaskletScheduleCall() {
    exists(Function f |
      f = this.getTarget() and
      (
        taskletHasName(f, "tasklet_schedule") or
        taskletHasName(f, "tasklet_hi_schedule") or
        taskletHasName(f, "tasklet_hi_schedule_first") or
        taskletHasName(f, "__tasklet_schedule") or
        taskletHasName(f, "__tasklet_hi_schedule")
      ) and
      this.getNumberOfArguments() > 0
    )
  }

  Expr getTaskletArg() { result = this.getArgument(0) }
  string getScheduleKind() { result = this.getTarget().getName() }
}

predicate immediateTaskletFreeArgument(Function target, int argumentIndex, string freeKind) {
  taskletHasName(target, "kfree") and argumentIndex = 0 and freeKind = "heap"
  or taskletHasName(target, "kfree_sensitive") and argumentIndex = 0 and freeKind = "heap_sensitive"
  or taskletHasName(target, "kfree_const") and argumentIndex = 0 and freeKind = "heap_or_const"
  or taskletHasName(target, "kzfree") and argumentIndex = 0 and freeKind = "heap_zeroed"
  or taskletHasName(target, "kvfree") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc"
  or taskletHasName(target, "kvfree_sensitive") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc_sensitive"
  or taskletHasName(target, "vfree") and argumentIndex = 0 and freeKind = "vmalloc"
  or taskletHasName(target, "vfree_atomic") and argumentIndex = 0 and freeKind = "vmalloc_atomic"
  or taskletHasName(target, "devm_kfree") and argumentIndex = 1 and freeKind = "device_managed_heap"
  or taskletHasName(target, "kmem_cache_free") and argumentIndex = 1 and freeKind = "slab_cache"
  or taskletHasName(target, "mempool_free") and argumentIndex = 0 and freeKind = "mempool"
  or taskletHasName(target, "free_percpu") and argumentIndex = 0 and freeKind = "percpu"
  or taskletHasName(target, "dma_free_coherent") and argumentIndex = 2 and freeKind = "dma_coherent"
  or taskletHasName(target, "dma_free_attrs") and argumentIndex = 2 and freeKind = "dma_attrs"
  or taskletHasName(target, "dma_free_noncoherent") and argumentIndex = 2 and freeKind = "dma_noncoherent"
  or taskletHasName(target, "dmam_free_coherent") and argumentIndex = 2 and freeKind = "device_managed_dma"
  or taskletHasName(target, "dma_pool_free") and argumentIndex = 1 and freeKind = "dma_pool"
  or taskletHasName(target, "pci_free_consistent") and argumentIndex = 2 and freeKind = "pci_consistent"
  or taskletHasName(target, "pci_pool_free") and argumentIndex = 1 and freeKind = "pci_pool"
  or taskletHasName(target, "usb_free_coherent") and argumentIndex = 2 and freeKind = "usb_coherent"
  or taskletHasName(target, "gen_pool_free") and argumentIndex = 1 and freeKind = "generic_pool"
  or taskletHasName(target, "free_pages") and argumentIndex = 0 and freeKind = "pages"
  or taskletHasName(target, "free_pages_exact") and argumentIndex = 0 and freeKind = "pages_exact"
  or taskletHasName(target, "__free_pages") and argumentIndex = 0 and freeKind = "pages_internal"
  or taskletHasName(target, "__free_page") and argumentIndex = 0 and freeKind = "page_internal"
  or taskletHasName(target, "free_page") and argumentIndex = 0 and freeKind = "page"
  or taskletHasName(target, "page_frag_free") and argumentIndex = 0 and freeKind = "page_frag"
  or taskletHasName(target, "free_netdev") and argumentIndex = 0 and freeKind = "netdev"
  or taskletHasName(target, "hci_free_dev") and argumentIndex = 0 and freeKind = "hci_dev"
  or taskletHasName(target, "usb_free_urb") and argumentIndex = 0 and freeKind = "usb_urb"
  or taskletHasName(target, "kfree_skb") and argumentIndex = 0 and freeKind = "skb"
  or taskletHasName(target, "dev_kfree_skb_any") and argumentIndex = 0 and freeKind = "skb"
  or taskletHasName(target, "consume_skb") and argumentIndex = 0 and freeKind = "skb"
  or taskletHasName(target, "kmem_cache_free_bulk") and argumentIndex = 2 and freeKind = "slab_cache_bulk"
  or taskletHasName(target, "kfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_heap"
  or taskletHasName(target, "kvfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_vm"
}

class TaskletFreeCall extends FunctionCall {
  TaskletFreeCall() {
    exists(int argumentIndex, string freeKind |
      immediateTaskletFreeArgument(this.getTarget(), argumentIndex, freeKind) and
      argumentIndex < this.getNumberOfArguments()
    )
  }

  int getFreedArgumentIndex() { immediateTaskletFreeArgument(this.getTarget(), result, _) }
  Expr getFreedExpr() { result = this.getArgument(this.getFreedArgumentIndex()) }
  string getFreeKind() { immediateTaskletFreeArgument(this.getTarget(), _, result) }
  string getFreeApi() { result = this.getTarget().getName() }
}

bindingset[before]
predicate taskletCfgStrictlyAfter(ControlFlowNode before, ControlFlowNode after) {
  before.getControlFlowScope() = after.getControlFlowScope() and
  before.getASuccessor+() = after
}

predicate taskletOwnerAndField(Expr taskletArg, Expr owner, Field taskletField) {
  exists(FieldAccess access |
    (
      access = taskletArg.getUnconverted()
      or exists(AddressOfExpr address |
        address = taskletArg.getUnconverted() and
        access = address.getOperand().getUnconverted()
      )
    ) and
    owner = access.getQualifier().getUnconverted() and
    taskletField = access.getTarget() and
    taskletField.getType().getUnspecifiedType().hasName("tasklet_struct")
  )
}

string taskletFieldIdentity(Field field) {
  result = field.getFile().getRelativePath() + ":" +
    field.getLocation().getStartLine().toString() + ":" +
    field.getLocation().getStartColumn().toString()
}

Expr taskletStripAddressExpr(Expr expression) {
  not expression.getUnconverted() instanceof AddressOfExpr and
  result = expression.getUnconverted()
  or
  exists(AddressOfExpr address |
    address = expression.getUnconverted() and
    result = address.getOperand().getUnconverted()
  )
}

bindingset[expression]
predicate taskletExprRootAndPath(
  Expr expression, Variable root,
  string identityPath, string displayPath, int depth
) {
  depth = 0 and
  exists(VariableAccess access |
    access = taskletStripAddressExpr(expression) and root = access.getTarget()
  ) and
  identityPath = "" and displayPath = ""
  or
  depth = 1 and taskletMaxTreeFieldDepth() >= 1 and
  exists(FieldAccess f1, VariableAccess access |
    f1 = taskletStripAddressExpr(expression) and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = taskletFieldIdentity(f1.getTarget()) and
    displayPath = f1.getTarget().getName()
  )
  or
  depth = 2 and taskletMaxTreeFieldDepth() >= 2 and
  exists(FieldAccess f1, FieldAccess f2, VariableAccess access |
    f2 = taskletStripAddressExpr(expression) and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = taskletFieldIdentity(f1.getTarget()) + "/" + taskletFieldIdentity(f2.getTarget()) and
    displayPath = f1.getTarget().getName() + "." + f2.getTarget().getName()
  )
  or
  depth = 3 and taskletMaxTreeFieldDepth() >= 3 and
  exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, VariableAccess access |
    f3 = taskletStripAddressExpr(expression) and
    f2 = f3.getQualifier().getUnconverted() and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget() and
    identityPath = taskletFieldIdentity(f1.getTarget()) + "/" +
      taskletFieldIdentity(f2.getTarget()) + "/" + taskletFieldIdentity(f3.getTarget()) and
    displayPath = f1.getTarget().getName() + "." +
      f2.getTarget().getName() + "." + f3.getTarget().getName()
  )
}

predicate taskletVariablePointsToType(Variable variable, Type targetType) {
  exists(PointerType pointer |
    pointer = variable.getType().getUnspecifiedType() and
    pointer.getBaseType().getUnspecifiedType() = targetType.getUnspecifiedType()
  )
}

bindingset[leftIdentity, rightIdentity]
string taskletJoinIdentityPath(string leftIdentity, string rightIdentity) {
  leftIdentity = "" and result = rightIdentity
  or rightIdentity = "" and result = leftIdentity
  or leftIdentity != "" and rightIdentity != "" and
    result = leftIdentity + "/" + rightIdentity
}

bindingset[leftDisplay, rightDisplay]
string taskletJoinDisplayPath(string leftDisplay, string rightDisplay) {
  leftDisplay = "" and result = rightDisplay
  or rightDisplay = "" and result = leftDisplay
  or leftDisplay != "" and rightDisplay != "" and
    result = leftDisplay + "." + rightDisplay
}

bindingset[prefix, full]
predicate taskletPathPrefix(string prefix, string full) {
  prefix = "" or prefix = full or full.indexOf(prefix + "/") = 0
}

predicate taskletTerminalRealFieldUse(FieldAccess use) {
  not exists(AddressOfExpr address |
    address.getOperand().getUnconverted() = use.getUnconverted()
  ) and
  not exists(FieldAccess outer |
    outer.getQualifier().getUnconverted() = use.getUnconverted()
  ) and
  (use.isRValue() or use.isModified() or use.isUsedAsLValue())
}

/** The declared tasklet field and registered tasklet callback are exact. */
predicate taskletSetupMatchesField(
  TaskletSetupCall setup, Field taskletField, Function callback
) {
  exists(Expr setupOwner |
    taskletOwnerAndField(setup.getTaskletArg(), setupOwner, taskletField) and
    callback = setup.getCallbackFunction()
  )
}

/** Direct tasklet_schedule*(&owner->tasklet). */
pragma[noinline]
predicate taskletDirectLifecycleAnchor(
  TaskletSetupCall setup, TaskletScheduleCall schedule, Field taskletField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(string identityPath, string displayPath, int depth |
    taskletSetupMatchesField(setup, taskletField, callback) and
    taskletOwnerAndField(schedule.getTaskletArg(), lifecycleOwner, taskletField) and
    taskletExprRootAndPath(
      lifecycleOwner, lifecycleRoot, identityPath, displayPath, depth
    ) and identityPath = "" and
    taskletVariablePointsToType(lifecycleRoot, taskletField.getDeclaringType()) and
    flowEntry = schedule
  )
}

/** Caller passes owner to a one-hop wrapper that performs tasklet_schedule*. */
pragma[noinline]
predicate taskletOwnerScheduleWrapperLifecycleAnchor(
  TaskletSetupCall setup, TaskletScheduleCall schedule, Field taskletField,
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
    taskletMaxWrapperDepth() >= 3 and
    taskletSetupMatchesField(setup, taskletField, callback) and
    taskletOwnerAndField(schedule.getTaskletArg(), scheduleOwner, taskletField) and
    taskletExprRootAndPath(
      scheduleOwner, scheduleRoot, scheduleIdentity, scheduleDisplay, scheduleDepth
    ) and scheduleIdentity = "" and
    calleeRoot = scheduleRoot and
    wrapper.getTarget() = schedule.getEnclosingFunction() and
    calleeRoot = wrapper.getTarget().getParameter(argumentIndex) and
    taskletExprRootAndPath(
      wrapper.getArgument(argumentIndex), callerRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and argumentIdentity = "" and
    taskletVariablePointsToType(callerRoot, taskletField.getDeclaringType()) and
    lifecycleOwner = wrapper.getArgument(argumentIndex).getUnconverted() and
    lifecycleRoot = callerRoot and flowEntry = wrapper
  )
}

/** Caller passes &owner->tasklet to a one-hop wrapper taking tasklet_struct *. */
pragma[noinline]
predicate taskletFieldScheduleWrapperLifecycleAnchor(
  TaskletSetupCall setup, TaskletScheduleCall schedule, Field taskletField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry
) {
  exists(
    FunctionCall wrapper, int argumentIndex, Parameter calleeTasklet,
    VariableAccess scheduleParameter,
    string ownerIdentity, string ownerDisplay, int ownerDepth
  |
    taskletMaxWrapperDepth() >= 3 and
    taskletSetupMatchesField(setup, taskletField, callback) and
    wrapper.getTarget() = schedule.getEnclosingFunction() and
    calleeTasklet = wrapper.getTarget().getParameter(argumentIndex) and
    scheduleParameter = schedule.getTaskletArg().getUnconverted() and
    scheduleParameter.getTarget() = calleeTasklet and
    taskletOwnerAndField(wrapper.getArgument(argumentIndex), lifecycleOwner, taskletField) and
    taskletExprRootAndPath(
      lifecycleOwner, lifecycleRoot, ownerIdentity, ownerDisplay, ownerDepth
    ) and ownerIdentity = "" and
    taskletVariablePointsToType(lifecycleRoot, taskletField.getDeclaringType()) and
    flowEntry = wrapper
  )
}

pragma[noinline]
predicate taskletAnyLifecycleAnchor(
  TaskletSetupCall setup, TaskletScheduleCall schedule, Field taskletField,
  Function callback, Expr lifecycleOwner, Variable lifecycleRoot,
  FunctionCall flowEntry, int scheduleWrapperDepth, string lifecycleBinding
) {
  taskletDirectLifecycleAnchor(
    setup, schedule, taskletField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and scheduleWrapperDepth = 0 and lifecycleBinding = "direct_schedule_exact_owner"
  or
  taskletOwnerScheduleWrapperLifecycleAnchor(
    setup, schedule, taskletField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and scheduleWrapperDepth = 1 and lifecycleBinding = "owner_schedule_wrapper_exact_parameter"
  or
  taskletFieldScheduleWrapperLifecycleAnchor(
    setup, schedule, taskletField, callback, lifecycleOwner, lifecycleRoot, flowEntry
  ) and scheduleWrapperDepth = 1 and lifecycleBinding = "tasklet_field_schedule_wrapper_exact_parameter"
}

/** container_of/from_tasklet with the exact embedded tasklet Field. */
predicate taskletModernCallbackOwner(
  Function callback, Field taskletField, Variable callbackOwner
) {
  exists(MacroInvocation recover, LocalVariable local, Initializer initializer |
    recover.getEnclosingFunction() = callback and
    recover.getUnexpandedArgument(2) = taskletField.getName() and
    local = callbackOwner and local.getFunction() = callback and
    initializer = local.getInitializer() and (initializer.getExpr() = recover.getExpr() or kernelLocalValueFlow(recover.getExpr(), local.getAnAccess())) and
    taskletVariablePointsToType(local, taskletField.getDeclaringType())
  )
}

/**
 * Old tasklet_init callback: the ulong callback parameter is cast back to the
 * owner, and setup argument 2 must originate from the same exact setup owner.
 */
predicate taskletOldCallbackOwner(
  TaskletSetupCall setup, Function callback,
  Field taskletField, Variable callbackOwner
) {
  exists(
    Parameter callbackData, LocalVariable local, Initializer initializer,
    VariableAccess callbackDataAccess,
    Expr setupOwner, Variable setupRoot, Variable dataRoot,
    string setupIdentity, string setupDisplay, int setupDepth,
    string dataIdentity, string dataDisplay, int dataDepth
  |
    taskletHasName(setup.getTarget(), "tasklet_init") and
    callbackData = callback.getParameter(0) and
    local = callbackOwner and local.getFunction() = callback and
    initializer = local.getInitializer() and
    callbackDataAccess = initializer.getExpr().getUnconverted() and
    callbackDataAccess.getTarget() = callbackData and
    taskletVariablePointsToType(local, taskletField.getDeclaringType()) and
    taskletOwnerAndField(setup.getTaskletArg(), setupOwner, taskletField) and
    taskletExprRootAndPath(
      setupOwner, setupRoot, setupIdentity, setupDisplay, setupDepth
    ) and setupIdentity = "" and
    taskletExprRootAndPath(
      setup.getDataArg(), dataRoot, dataIdentity, dataDisplay, dataDepth
    ) and dataIdentity = "" and setupRoot = dataRoot
  )
}

predicate taskletCallbackOwnerSeed(
  TaskletSetupCall setup, Function callback, Field taskletField,
  Variable callbackOwner, string recoveryKind
) {
  taskletModernCallbackOwner(callback, taskletField, callbackOwner) and
  recoveryKind = "container_of_or_from_tasklet_exact_field"
  or
  taskletOldCallbackOwner(setup, callback, taskletField, callbackOwner) and
  recoveryKind = "tasklet_init_exact_ulong_owner"
}

Function taskletVariableFunction(Variable variable) {
  exists(Parameter parameter |
    variable = parameter and result = parameter.getFunction()
  )
  or
  exists(LocalVariable local |
    variable = local and result = local.getFunction()
  )
}

pragma[noinline]
predicate taskletDirectCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(int useDepth |
    use.getEnclosingFunction() = taskletVariableFunction(callbackOwner) and
    taskletTerminalRealFieldUse(use) and
    taskletExprRootAndPath(
      use, callbackOwner, useIdentityPath, useDisplayPath, useDepth
    )
  )
}

pragma[noinline]
predicate taskletOneHopCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    taskletMaxWrapperDepth() >= 3 and
    helperCall.getEnclosingFunction() = taskletVariableFunction(callbackOwner) and
    taskletExprRootAndPath(
      helperCall.getArgument(argumentIndex), callbackOwner,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    use.getEnclosingFunction() = helperRoot.getFunction() and
    taskletTerminalRealFieldUse(use) and
    taskletExprRootAndPath(
      use, helperRoot, helperIdentity, helperDisplay, helperDepth
    ) and
    useIdentityPath = taskletJoinIdentityPath(argumentIdentity, helperIdentity) and
    useDisplayPath = taskletJoinDisplayPath(argumentDisplay, helperDisplay)
  )
}

pragma[noinline]
predicate taskletTwoHopCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath
) {
  exists(
    FunctionCall firstCall, FunctionCall secondCall,
    int firstIndex, int secondIndex,
    string firstIdentity, string firstDisplay, int firstDepth,
    string secondIdentity, string secondDisplay, int secondDepth, int useDepth,
    Parameter firstRoot, Parameter secondRoot
  |
    taskletMaxWrapperDepth() >= 3 and
    firstCall.getEnclosingFunction() = taskletVariableFunction(callbackOwner) and
    taskletExprRootAndPath(firstCall.getArgument(firstIndex), callbackOwner,
      firstIdentity, firstDisplay, firstDepth) and
    firstRoot = firstCall.getTarget().getParameter(firstIndex) and
    secondCall.getEnclosingFunction() = firstRoot.getFunction() and
    taskletExprRootAndPath(secondCall.getArgument(secondIndex), firstRoot,
      secondIdentity, secondDisplay, secondDepth) and
    secondRoot = secondCall.getTarget().getParameter(secondIndex) and
    use.getEnclosingFunction() = secondRoot.getFunction() and
    taskletTerminalRealFieldUse(use) and
    taskletExprRootAndPath(use, secondRoot, useIdentityPath, useDisplayPath, useDepth) and
    useIdentityPath = taskletJoinIdentityPath(taskletJoinIdentityPath(firstIdentity, secondIdentity), useIdentityPath) and
    useDisplayPath = taskletJoinDisplayPath(taskletJoinDisplayPath(firstDisplay, secondDisplay), useDisplayPath)
  )
}
predicate taskletAnyCallbackRealUse(
  Variable callbackOwner, FieldAccess use,
  string useIdentityPath, string useDisplayPath, int callbackCallDepth
) {
  taskletDirectCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 0
  or
  taskletOneHopCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 1
  or
  taskletTwoHopCallbackRealUse(
    callbackOwner, use, useIdentityPath, useDisplayPath
  ) and callbackCallDepth = 2
}

/**
 * Materialize the rare exact setup/field/callback/lifecycle binding before
 * scanning callback bodies.  On large kernel databases this prevents the
 * optimizer from expanding every FieldAccess before the tasklet seed is known.
 */
newtype TTaskletBoundLifecycle =
  MkTaskletBoundLifecycle(
    TaskletSetupCall setup, TaskletScheduleCall schedule, Field taskletField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner, Variable lifecycleRoot,
    int scheduleWrapperDepth, string lifecycleBinding
  ) {
    taskletAnyLifecycleAnchor(
      setup, schedule, taskletField, callback, lifecycleOwner, lifecycleRoot,
      flowEntry, scheduleWrapperDepth, lifecycleBinding
    ) and
    taskletCallbackOwnerSeed(
      setup, callback, taskletField, callbackOwner, callbackRecovery
    )
  }

class TaskletBoundLifecycle extends TTaskletBoundLifecycle {
  TaskletSetupCall setup;
  TaskletScheduleCall schedule;
  Field taskletField;
  Function callback;
  Variable callbackOwner;
  string callbackRecovery;
  FunctionCall flowEntry;
  Expr lifecycleOwner;
  Variable lifecycleRoot;
  int scheduleWrapperDepth;
  string lifecycleBinding;

  TaskletBoundLifecycle() {
    this = MkTaskletBoundLifecycle(
      setup, schedule, taskletField, callback, callbackOwner, callbackRecovery,
      flowEntry, lifecycleOwner, lifecycleRoot,
      scheduleWrapperDepth, lifecycleBinding
    )
  }

  TaskletSetupCall getSetup() { result = setup }
  TaskletScheduleCall getSchedule() { result = schedule }
  Field getTaskletField() { result = taskletField }
  Function getCallback() { result = callback }
  Variable getCallbackOwner() { result = callbackOwner }
  string getCallbackRecovery() { result = callbackRecovery }
  FunctionCall getFlowEntry() { result = flowEntry }
  Expr getLifecycleOwner() { result = lifecycleOwner }
  Variable getLifecycleRoot() { result = lifecycleRoot }
  int getScheduleWrapperDepth() { result = scheduleWrapperDepth }
  string getLifecycleBinding() { result = lifecycleBinding }
  string toString() { result = "tasklet-bound-lifecycle" }
}

/** Materialize only concrete terminal callback accesses for the bound seed. */
newtype TTaskletBoundUse =
  MkTaskletBoundUse(
    TaskletBoundLifecycle lifecycle, FieldAccess use,
    string useIdentityPath, string useDisplayPath, int callbackCallDepth
  ) {
    taskletAnyCallbackRealUse(
      lifecycle.getCallbackOwner(), use,
      useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

class TaskletBoundUse extends TTaskletBoundUse {
  TaskletBoundLifecycle lifecycle;
  FieldAccess use;
  string useIdentityPath;
  string useDisplayPath;
  int callbackCallDepth;

  TaskletBoundUse() {
    this = MkTaskletBoundUse(
      lifecycle, use, useIdentityPath, useDisplayPath, callbackCallDepth
    )
  }

  TaskletBoundLifecycle getLifecycle() { result = lifecycle }
  FieldAccess getUse() { result = use }
  string getUseIdentityPath() { result = useIdentityPath }
  string getUseDisplayPath() { result = useDisplayPath }
  int getCallbackCallDepth() { result = callbackCallDepth }
  string toString() { result = "tasklet-bound-use" }
}

predicate taskletTeardownLikeFunction(Function function) {
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
 * Keeping these tuples independent of TaskletBoundUse is important: otherwise
 * the evaluator may repeatedly join every callback FieldAccess with every
 * free call before it can apply the file, owner-type, and path restrictions.
 */
newtype TTaskletCrossDirectFreeSeed =
  MkTaskletCrossDirectFreeSeed(
    Type ownerType, Function teardown, TaskletFreeCall free,
    string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
  ) {
    teardown = free.getEnclosingFunction() and
    taskletTeardownLikeFunction(teardown) and
    exists(Variable freeRoot, PointerType ownerPointer |
      taskletExprRootAndPath(
        free.getFreedExpr(), freeRoot,
        freeIdentityPath, freeDisplayPath, freedFieldDepth
      ) and
      ownerPointer = freeRoot.getType().getUnspecifiedType() and
      ownerType = ownerPointer.getBaseType().getUnspecifiedType()
    )
  }

class TaskletCrossDirectFreeSeed extends TTaskletCrossDirectFreeSeed {
  Type ownerType;
  Function teardown;
  TaskletFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freedFieldDepth;

  TaskletCrossDirectFreeSeed() {
    this = MkTaskletCrossDirectFreeSeed(
      ownerType, teardown, free,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

  Type getOwnerType() { result = ownerType }
  Function getTeardown() { result = teardown }
  TaskletFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string toString() { result = "tasklet-cross-direct-free-seed" }
}

newtype TTaskletCrossOneHopFreeSeed =
  MkTaskletCrossOneHopFreeSeed(
    Type ownerType, Function teardown, TaskletFreeCall free,
    string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
  ) {
    exists(
      FunctionCall helperCall, int argumentIndex,
      Variable teardownRoot, PointerType ownerPointer,
      string argumentIdentity, string argumentDisplay, int argumentDepth,
      Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
    |
      taskletMaxWrapperDepth() >= 3 and
      teardown = helperCall.getEnclosingFunction() and
      taskletTeardownLikeFunction(teardown) and
      not helperCall instanceof TaskletFreeCall and
      taskletExprRootAndPath(
        helperCall.getArgument(argumentIndex), teardownRoot,
        argumentIdentity, argumentDisplay, argumentDepth
      ) and
      ownerPointer = teardownRoot.getType().getUnspecifiedType() and
      ownerType = ownerPointer.getBaseType().getUnspecifiedType() and
      helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
      free.getEnclosingFunction() = helperRoot.getFunction() and
      taskletExprRootAndPath(
        free.getFreedExpr(), helperRoot,
        helperIdentity, helperDisplay, helperDepth
      ) and
      freeIdentityPath = taskletJoinIdentityPath(argumentIdentity, helperIdentity) and
      freeDisplayPath = taskletJoinDisplayPath(argumentDisplay, helperDisplay) and
      freedFieldDepth = argumentDepth + helperDepth
    )
  }

class TaskletCrossOneHopFreeSeed extends TTaskletCrossOneHopFreeSeed {
  Type ownerType;
  Function teardown;
  TaskletFreeCall free;
  string freeIdentityPath;
  string freeDisplayPath;
  int freedFieldDepth;

  TaskletCrossOneHopFreeSeed() {
    this = MkTaskletCrossOneHopFreeSeed(
      ownerType, teardown, free,
      freeIdentityPath, freeDisplayPath, freedFieldDepth
    )
  }

  Type getOwnerType() { result = ownerType }
  Function getTeardown() { result = teardown }
  TaskletFreeCall getFree() { result = free }
  string getFreeIdentityPath() { result = freeIdentityPath }
  string getFreeDisplayPath() { result = freeDisplayPath }
  int getFreedFieldDepth() { result = freedFieldDepth }
  string toString() { result = "tasklet-cross-one-hop-free-seed" }
}

pragma[noinline]
predicate taskletCallerDirectFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  TaskletBoundUse boundUse, TaskletFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  free.getEnclosingFunction() = flowEntry.getEnclosingFunction() and
  free.getLocation().getStartLine() > flowEntry.getLocation().getStartLine() and
  taskletExprRootAndPath(
    free.getFreedExpr(), lifecycleRoot,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and
  taskletPathPrefix(freeIdentityPath, boundUse.getUseIdentityPath())
}

pragma[noinline]
predicate taskletCallerOneHopFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot,
  TaskletBoundUse boundUse, TaskletFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(
    FunctionCall helperCall, int argumentIndex,
    string argumentIdentity, string argumentDisplay, int argumentDepth,
    Parameter helperRoot, string helperIdentity, string helperDisplay, int helperDepth
  |
    taskletMaxWrapperDepth() >= 3 and
    helperCall.getEnclosingFunction() = flowEntry.getEnclosingFunction() and
    helperCall.getLocation().getStartLine() > flowEntry.getLocation().getStartLine() and
    not helperCall instanceof TaskletFreeCall and
    taskletExprRootAndPath(
      helperCall.getArgument(argumentIndex), lifecycleRoot,
      argumentIdentity, argumentDisplay, argumentDepth
    ) and
    helperRoot = helperCall.getTarget().getParameter(argumentIndex) and
    free.getEnclosingFunction() = helperRoot.getFunction() and
    taskletExprRootAndPath(
      free.getFreedExpr(), helperRoot,
      helperIdentity, helperDisplay, helperDepth
    ) and
    freeIdentityPath = taskletJoinIdentityPath(argumentIdentity, helperIdentity) and
    freeDisplayPath = taskletJoinDisplayPath(argumentDisplay, helperDisplay) and
    freedFieldDepth = argumentDepth + helperDepth and
    taskletPathPrefix(freeIdentityPath, boundUse.getUseIdentityPath())
  )
}

pragma[noinline]
predicate taskletCrossLifecycleDirectFreeFinding(
  FunctionCall flowEntry, Field taskletField, Function callback,
  TaskletBoundUse boundUse, TaskletFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(TaskletCrossDirectFreeSeed seed |
    seed.getTeardown() != flowEntry.getEnclosingFunction() and
    seed.getTeardown() != callback and
    seed.getOwnerType() = taskletField.getDeclaringType().getUnspecifiedType() and
    free = seed.getFree() and
    freeIdentityPath = seed.getFreeIdentityPath() and
    freeDisplayPath = seed.getFreeDisplayPath() and
    freedFieldDepth = seed.getFreedFieldDepth() and
    taskletPathPrefix(seed.getFreeIdentityPath(), boundUse.getUseIdentityPath())
  )
}

pragma[noinline]
predicate taskletCrossLifecycleOneHopFreeFinding(
  FunctionCall flowEntry, Field taskletField, Function callback,
  TaskletBoundUse boundUse, TaskletFreeCall free,
  string freeIdentityPath, string freeDisplayPath, int freedFieldDepth
) {
  exists(TaskletCrossOneHopFreeSeed seed |
    seed.getTeardown() != flowEntry.getEnclosingFunction() and
    seed.getTeardown() != callback and
    seed.getOwnerType() = taskletField.getDeclaringType().getUnspecifiedType() and
    free = seed.getFree() and
    freeIdentityPath = seed.getFreeIdentityPath() and
    freeDisplayPath = seed.getFreeDisplayPath() and
    freedFieldDepth = seed.getFreedFieldDepth() and
    taskletPathPrefix(seed.getFreeIdentityPath(), boundUse.getUseIdentityPath())
  )
}

pragma[noinline]
predicate taskletAnyFreeFinding(
  FunctionCall flowEntry, Variable lifecycleRoot, Field taskletField, Function callback,
  TaskletBoundUse boundUse, TaskletFreeCall free,
  string freeIdentityPath, string freeDisplayPath,
  int freeCallDepth, int freedFieldDepth, string flowMode
) {
  taskletCallerDirectFreeFinding(
    flowEntry, lifecycleRoot, boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "direct_cfg_free"
  or
  taskletCallerOneHopFreeFinding(
    flowEntry, lifecycleRoot, boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "caller_one_hop_free"
  or
  taskletCrossLifecycleDirectFreeFinding(
    flowEntry, taskletField, callback,
    boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 0 and flowMode = "cross_lifecycle_teardown_root"
  or
  taskletCrossLifecycleOneHopFreeFinding(
    flowEntry, taskletField, callback,
    boundUse, free,
    freeIdentityPath, freeDisplayPath, freedFieldDepth
  ) and freeCallDepth = 1 and flowMode = "cross_lifecycle_one_hop_free"
}

bindingset[depth]
string taskletFreedRegionKind(int depth) {
  depth = 0 and result = "whole_tasklet_owner"
  or depth > 0 and result = "nested_subtree_of_tasklet_owner"
}

class TaskletBarrierCall extends FunctionCall {
  TaskletBarrierCall() {
    taskletHasName(this.getTarget(), "tasklet_disable") or
    taskletHasName(this.getTarget(), "tasklet_disable_nosync") or
    taskletHasName(this.getTarget(), "tasklet_kill") or
    taskletHasName(this.getTarget(), "tasklet_kill_immediate") or
    taskletHasName(this.getTarget(), "tasklet_unlock_wait")
  }

  string getApiName() { result = this.getTarget().getName() }
  string getStrength() {
    (
      taskletHasName(this.getTarget(), "tasklet_disable") or
      taskletHasName(this.getTarget(), "tasklet_kill")
    ) and result = "strong"
    or
    (
      taskletHasName(this.getTarget(), "tasklet_disable_nosync") or
      taskletHasName(this.getTarget(), "tasklet_kill_immediate") or
      taskletHasName(this.getTarget(), "tasklet_unlock_wait")
    ) and result = "weak"
  }
}

string taskletBarrierSummaryForFree(TaskletFreeCall free) {
  exists(TaskletBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    result = barrier.getStrength() + "_barrier_before_free:" + barrier.getApiName()
  )
  or
  not exists(TaskletBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "none_in_free_function_before_free"
}

string taskletProtectionTagForFree(TaskletFreeCall free) {
  exists(TaskletBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(TaskletBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "strong"
  ) and
  exists(TaskletBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine() and
    barrier.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(TaskletBarrierCall barrier |
    barrier.getEnclosingFunction() = free.getEnclosingFunction() and
    barrier.getLocation().getStartLine() <= free.getLocation().getStartLine()
  ) and result = "no"
}

newtype TTaskletConcurrentFreeRow =
  MkTaskletConcurrentFreeRow(
    TaskletSetupCall setup, TaskletScheduleCall schedule, Field taskletField,
    Function callback, Variable callbackOwner, string callbackRecovery,
    FunctionCall flowEntry, Expr lifecycleOwner,
    int scheduleWrapperDepth, string lifecycleBinding,
    FieldAccess matchedUse, string useIdentityPath, string useDisplayPath,
    int callbackCallDepth,
    TaskletFreeCall free, string freeDisplayPath,
    int freeCallDepth, int freedFieldDepth, string flowMode
  ) {
    exists(
      TaskletBoundUse boundUse, TaskletBoundLifecycle lifecycle,
      string freeIdentityPath
    |
      boundUse.getLifecycle() = lifecycle and
      setup = lifecycle.getSetup() and
      schedule = lifecycle.getSchedule() and
      taskletField = lifecycle.getTaskletField() and
      callback = lifecycle.getCallback() and
      callbackOwner = lifecycle.getCallbackOwner() and
      callbackRecovery = lifecycle.getCallbackRecovery() and
      flowEntry = lifecycle.getFlowEntry() and
      lifecycleOwner = lifecycle.getLifecycleOwner() and
      scheduleWrapperDepth = lifecycle.getScheduleWrapperDepth() and
      lifecycleBinding = lifecycle.getLifecycleBinding() and
      matchedUse = boundUse.getUse() and
      useIdentityPath = boundUse.getUseIdentityPath() and
      useDisplayPath = boundUse.getUseDisplayPath() and
      callbackCallDepth = boundUse.getCallbackCallDepth() and
      taskletAnyFreeFinding(
        flowEntry, lifecycle.getLifecycleRoot(), taskletField, callback,
        boundUse, free,
        freeIdentityPath, freeDisplayPath,
        freeCallDepth, freedFieldDepth, flowMode
      )
    )
  }

class TaskletConcurrentFreeRow extends TTaskletConcurrentFreeRow {
  TaskletSetupCall setup;
  TaskletScheduleCall schedule;
  Field taskletField;
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
  TaskletFreeCall free;
  string freeDisplayPath;
  int freeCallDepth;
  int freedFieldDepth;
  string flowMode;

  TaskletConcurrentFreeRow() {
    this = MkTaskletConcurrentFreeRow(
      setup, schedule, taskletField,
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
  pragma[noinline] string getSetupBinding() { result = taskletField.getName() }

  pragma[noinline] string getCallbackName() { result = callback.getName() }
  pragma[noinline] string getCallbackFile() { result = callback.getFile().getRelativePath() }
  pragma[noinline] int getCallbackLine() { result = callback.getLocation().getStartLine() }
  pragma[noinline] string getCallbackRecovery() { result = callbackRecovery }
  pragma[noinline] string getCallbackKind() { result = setup.getSetupKind() }
  pragma[noinline] int getCallbackCallDepth() { result = callbackCallDepth }

  pragma[noinline] string getHolderFunction() { result = flowEntry.getEnclosingFunction().getName() }
  pragma[noinline] string getHolderRoot() { result = lifecycleOwner.toString() }
  pragma[noinline] string getHolderType() { result = taskletField.getDeclaringType().toString() }
  pragma[noinline] string getTaskletFieldName() { result = taskletField.getName() }

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
    result = taskletFreedRegionKind(freedFieldDepth) + ";" + flowMode
  }

  pragma[noinline] string getUseFile() { result = matchedUse.getFile().getRelativePath() }
  pragma[noinline] int getUseLine() { result = matchedUse.getLocation().getStartLine() }
  pragma[noinline] string getUseFunction() { result = matchedUse.getEnclosingFunction().getName() }
  pragma[noinline] string getUseExpression() { result = matchedUse.toString() }
  pragma[noinline] string getUsedObjectPath() {
    useDisplayPath = "" and result = "<owner>"
    or useDisplayPath != "" and result = useDisplayPath
  }
  pragma[noinline] string getBarrierContext() { result = taskletBarrierSummaryForFree(free) }
  pragma[noinline] string getProtectionTag() { result = taskletProtectionTagForFree(free) }

  string toString() { result = "tasklet-concurrent-free-row" }
}
