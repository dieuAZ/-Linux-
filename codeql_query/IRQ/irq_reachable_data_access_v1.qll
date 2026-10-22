/**
 * irq_reachable_data_access_v1.qll
 *
 * 复用 kthread fast-recall v4.1 的核心结构：
 *   holder 公共根 -> IRQ 注册 dev_id / free 参数 -> IRQ 回调参数 -> 有限深度传播。
 *
 * 性能原则：
 * 1. holder 和 IRQ 回调两侧均只做有限深度递归；
 * 2. IRQ 递归状态只携带 registration + entry + seedDataPath；
 * 3. 不把 sink/holder/root 带入 IRQ 递归，避免生命周期候选与回调传播笛卡尔放大；
 * 4. 递归谓词不使用 bindingset，避免 CodeQL 2.25.0 的递归内联错误。
 */

import cpp
import find_before
import irq_fast_recall_config_v1
import kthread.container_of_kernel_v1

class IrqRegistrationCallV1 extends FunctionCall {
  IrqRegistrationCallV1() {
    this.getTarget().hasName("request_irq") or
    this.getTarget().hasName("request_threaded_irq") or
    this.getTarget().hasName("devm_request_irq") or
    this.getTarget().hasName("devm_request_threaded_irq") or
    this.getTarget().hasName("request_any_context_irq") or
    this.getTarget().hasName("devm_request_any_context_irq") or
    this.getTarget().hasName("request_percpu_irq") or
    this.getTarget().hasName("devm_request_percpu_irq") or
    this.getTarget().hasName("request_nmi")
  }
}

predicate knownIrqRegistrationMacroV1(string name) {
  name = "request_irq" or
  name = "request_threaded_irq" or
  name = "devm_request_irq" or
  name = "devm_request_threaded_irq" or
  name = "request_any_context_irq" or
  name = "devm_request_any_context_irq" or
  name = "request_percpu_irq" or
  name = "devm_request_percpu_irq" or
  name = "request_nmi"
}

predicate expandedFromKnownIrqMacroV1(IrqRegistrationCallV1 registration) {
  exists(MacroInvocation mi |
    mi.getAnExpandedElement() = registration and
    knownIrqRegistrationMacroV1(mi.getMacroName())
  )
}

/** 尽量输出源码层 API；没有宏信息时回退到实际 target。 */
string irqSourceRegistrationApiV1(IrqRegistrationCallV1 registration) {
  exists(MacroInvocation mi |
    mi.getAnExpandedElement() = registration and
    knownIrqRegistrationMacroV1(mi.getMacroName()) and
    result = mi.getMacroName()
  )
  or
  not expandedFromKnownIrqMacroV1(registration) and
  result = registration.getTarget().getName()
}

string irqRegistrationKindV1(IrqRegistrationCallV1 registration) {
  irqSourceRegistrationApiV1(registration) = "devm_request_percpu_irq" and
  result = "managed_percpu"
  or
  irqSourceRegistrationApiV1(registration) = "request_percpu_irq" and
  result = "percpu"
  or
  irqSourceRegistrationApiV1(registration) = "devm_request_any_context_irq" and
  result = "managed_any_context"
  or
  irqSourceRegistrationApiV1(registration) = "request_any_context_irq" and
  result = "any_context"
  or
  (
    irqSourceRegistrationApiV1(registration) = "devm_request_irq" or
    irqSourceRegistrationApiV1(registration) = "devm_request_threaded_irq"
  ) and
  result = "managed"
  or
  (
    irqSourceRegistrationApiV1(registration) = "request_irq" or
    irqSourceRegistrationApiV1(registration) = "request_threaded_irq"
  ) and
  result = "unmanaged"
  or
  irqSourceRegistrationApiV1(registration) = "request_nmi" and
  result = "nmi"
}

/** 确定性剥离括号、cast、取地址。 */
Expr stripExprV1(Expr e) {
  exists(ParenthesisExpr p |
    e = p and result = stripExprV1(p.getExpr())
  )
  or
  exists(Cast c |
    e = c and result = stripExprV1(c.getExpr())
  )
  or
  exists(AddressOfExpr a |
    e = a and result = stripExprV1(a.getOperand())
  )
  or
  not e instanceof ParenthesisExpr and
  not e instanceof Cast and
  not e instanceof AddressOfExpr and
  result = e
}

bindingset[a, b]
string joinPathV1(string a, string b) {
  a = "" and result = b
  or
  b = "" and result = a
  or
  a != "" and b != "" and result = a + "." + b
}

bindingset[prefix, full]
predicate pathIsSameOrDescendantV1(string prefix, string full) {
  prefix = ""
  or
  full = prefix
  or
  exists(string suffix |
    suffix != "" and full = prefix + "." + suffix
  )
}

predicate exprPathFromVarRootV1(Variable v, Expr e, string path) {
  exists(VariableAccess va |
    stripExprV1(e) = va and
    va.getTarget() = v and
    path = ""
  )
  or
  exists(FieldAccess fa, string basePath |
    stripExprV1(e) = fa and
    exprPathFromVarRootV1(v, fa.getQualifier(), basePath) and
    path = joinPathV1(basePath, fa.getTarget().getName())
  )
}

bindingset[txt]
private predicate exprMatchesContainerArgTextV1(Expr e, string txt) {
  e.toString() = txt or stripExprV1(e).toString() = txt
}

/** Recover the owner path from container_of/list_entry/from_timer-style macros. */
bindingset[sourceVar, sourcePath, f, containerExpr]
private predicate containerPathFromTrackedVariableV1(
  Variable sourceVar,
  string sourcePath,
  Function f,
  Expr containerExpr,
  string fullPath
) {
  exists(
    ContainerLikeMacro macro, Expr macroResult, Expr pointerArg,
    string pointerText, string member, string relativePointerPath,
    string pointerFullPath
  |
    macroResult = macro.getExpr() and
    stripExprV1(containerExpr) = stripExprV1(macroResult) and
    macroResult.getEnclosingFunction() = f and
    pointerArg.getEnclosingFunction() = f and
    containerLikePtrArgText(macro, pointerText) and
    containerLikeMemberText(macro, member) and
    exprMatchesContainerArgTextV1(pointerArg, pointerText) and
    exprPathFromVarRootV1(sourceVar, pointerArg, relativePointerPath) and
    pointerFullPath = joinPathV1(sourcePath, relativePointerPath) and
    stripContainerMember(pointerFullPath, member, fullPath)
  )
}

predicate rootBelongsToHolderV1(Variable root, Function holder) {
  exists(Parameter p |
    root = p and p.getFunction() = holder
  )
  or
  exists(LocalVariable v |
    root = v and
    v.getFunction() = holder and
    not v.isStatic() and
    not v.isCompilerGenerated()
  )
  or
  exists(GlobalVariable g, VariableAccess access |
    root = g and
    access.getTarget() = g and
    access.getEnclosingFunction() = holder
  )
}

string holderRootKindV1(Variable root) {
  root instanceof Parameter and result = "parameter"
  or
  root instanceof LocalVariable and result = "local_variable"
  or
  root instanceof GlobalVariable and result = "global_variable"
}

/** 精确深度的普通直接调用可达关系。 */
predicate directCallReachableAtDepthV1(Function src, Function dst, int depth) {
  depth = 0 and src = dst
  or
  exists(Function next, int previousDepth |
    previousDepth >= 0 and
    previousDepth < maxBoundedCallDepth() and
    depth = previousDepth + 1 and
    allowedCallBridgeFunctionV1(src) and
    allowedCallBridgeFunctionV1(next) and
    directCaller(src, next) and
    directCallReachableAtDepthV1(next, dst, previousDepth)
  )
}

predicate holderReachesRegistrationOwnerV1(
  Function holder, IrqRegistrationCallV1 registration, int depth
) {
  depth >= 0 and
  depth <= maxHolderToRegistrationCallDepth() and
  directCallReachableAtDepthV1(holder, registration.getEnclosingFunction(), depth)
}

predicate holderReachesFreeOwnerV1(
  Function holder, FreeLikeSink sink, int depth
) {
  depth >= 0 and
  depth <= maxHolderToFreeCallDepth() and
  directCallReachableAtDepthV1(holder, sinkOwner(sink), depth)
}

/** 根据实际 target 的签名取 IRQ 号参数。 */
Expr irqNumberArgV1(IrqRegistrationCallV1 registration) {
  (
    registration.getTarget().hasName("request_irq") or
    registration.getTarget().hasName("request_threaded_irq") or
    registration.getTarget().hasName("request_any_context_irq") or
    registration.getTarget().hasName("request_percpu_irq") or
    registration.getTarget().hasName("request_nmi")
  ) and
  result = stripExprV1(registration.getArgument(0))
  or
  (
    registration.getTarget().hasName("devm_request_irq") or
    registration.getTarget().hasName("devm_request_threaded_irq") or
    registration.getTarget().hasName("devm_request_any_context_irq") or
    registration.getTarget().hasName("devm_request_percpu_irq")
  ) and
  result = stripExprV1(registration.getArgument(1))
}

/** 根据实际 target 的签名取 hard handler 参数。 */
Expr irqHardHandlerArgV1(IrqRegistrationCallV1 registration) {
  (
    registration.getTarget().hasName("request_irq") or
    registration.getTarget().hasName("request_threaded_irq") or
    registration.getTarget().hasName("request_any_context_irq") or
    registration.getTarget().hasName("request_percpu_irq") or
    registration.getTarget().hasName("request_nmi")
  ) and
  result = stripExprV1(registration.getArgument(1))
  or
  (
    registration.getTarget().hasName("devm_request_irq") or
    registration.getTarget().hasName("devm_request_threaded_irq") or
    registration.getTarget().hasName("devm_request_any_context_irq") or
    registration.getTarget().hasName("devm_request_percpu_irq")
  ) and
  result = stripExprV1(registration.getArgument(2))
}

/** 仅 threaded IRQ API 有 thread_fn 参数。 */
Expr irqThreadHandlerArgV1(IrqRegistrationCallV1 registration) {
  registration.getTarget().hasName("request_threaded_irq") and
  result = stripExprV1(registration.getArgument(2))
  or
  registration.getTarget().hasName("devm_request_threaded_irq") and
  result = stripExprV1(registration.getArgument(3))
}

/** 根据实际 target 的签名取 dev_id/percpu_dev_id。 */
Expr irqDevIdArgV1(IrqRegistrationCallV1 registration) {
  (
    registration.getTarget().hasName("request_irq") or
    registration.getTarget().hasName("request_any_context_irq") or
    registration.getTarget().hasName("request_nmi")
  ) and
  result = stripExprV1(registration.getArgument(4))
  or
  registration.getTarget().hasName("request_threaded_irq") and
  result = stripExprV1(registration.getArgument(5))
  or
  (
    registration.getTarget().hasName("devm_request_irq") or
    registration.getTarget().hasName("devm_request_any_context_irq")
  ) and
  result = stripExprV1(registration.getArgument(5))
  or
  registration.getTarget().hasName("devm_request_threaded_irq") and
  result = stripExprV1(registration.getArgument(6))
  or
  registration.getTarget().hasName("request_percpu_irq") and
  result = stripExprV1(registration.getArgument(3))
  or
  registration.getTarget().hasName("devm_request_percpu_irq") and
  result = stripExprV1(registration.getArgument(4))
}

/** 一个注册点可产生 hardirq 和/或 threaded_irq 两个入口。 */
predicate irqEntryFunctionV1(
  IrqRegistrationCallV1 registration, Function entry, string handlerKind
) {
  exists(FunctionAccess fa |
    fa = irqHardHandlerArgV1(registration) and
    entry = fa.getTarget() and
    handlerKind = "hardirq"
  )
  or
  exists(FunctionAccess fa |
    fa = irqThreadHandlerArgV1(registration) and
    entry = fa.getTarget() and
    handlerKind = "threaded_irq"
  )
}

Parameter irqEntryDataParamV1(
  IrqRegistrationCallV1 registration, Function entry
) {
  exists(string handlerKind |
    irqEntryFunctionV1(registration, entry, handlerKind) and
    result = entry.getParameter(1)
  )
}

Expr freeObjectArgV1(FreeLikeSink sink) {
  result = stripExprV1(sink.getArgument(sink.getFreedArgumentIndex()))
}

/** holder 侧有限传播。 */
predicate trackedHolderVariableCoreV1(
  Function holder,
  Variable root,
  Function f,
  Variable v,
  string path,
  int callDepth,
  int aliasHops
) {
  rootBelongsToHolderV1(root, holder) and
  f = holder and
  v = root and
  path = "" and
  callDepth = 0 and
  aliasHops = 0
  or
  exists(
    Function caller, Function callee, FunctionCall call,
    Variable sourceVar, string sourcePath, string relativePath,
    int sourceCallDepth, int sourceAliasHops, int i
  |
    trackedHolderVariableCoreV1(
      holder, root, caller, sourceVar, sourcePath, sourceCallDepth, sourceAliasHops
    ) and
    sourceCallDepth < maxHolderDataFlowDepth() and
    allowedCallBridgeFunctionV1(callee) and
    caller.calls(callee, call) and
    exprPathFromVarRootV1(sourceVar, call.getArgument(i), relativePath) and
    f = callee and
    v = callee.getParameter(i) and
    path = joinPathV1(sourcePath, relativePath) and
    callDepth = sourceCallDepth + 1 and
    aliasHops = sourceAliasHops
  )
  or
  exists(
    LocalVariable local, Initializer init0, Expr rhs,
    Variable sourceVar, string sourcePath, string relativePath,
    int sourceCallDepth, int sourceAliasHops
  |
    local = v and
    local.getFunction() = f and
    init0 = local.getInitializer() and
    rhs = init0.getExpr() and
    trackedHolderVariableCoreV1(
      holder, root, f, sourceVar, sourcePath, sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxHolderLocalAliasHops() and
    exprPathFromVarRootV1(sourceVar, rhs, relativePath) and
    path = joinPathV1(sourcePath, relativePath) and
    callDepth = sourceCallDepth and
    aliasHops = sourceAliasHops + 1
  )
  or
  exists(
    LocalVariable local, AssignExpr assignment, VariableAccess lhs, Expr rhs,
    Variable sourceVar, string sourcePath, string relativePath,
    int sourceCallDepth, int sourceAliasHops
  |
    local = v and
    local.getFunction() = f and
    assignment.getEnclosingFunction() = f and
    lhs = stripExprV1(assignment.getLValue()) and
    lhs.getTarget() = local and
    rhs = assignment.getRValue() and
    trackedHolderVariableCoreV1(
      holder, root, f, sourceVar, sourcePath, sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxHolderLocalAliasHops() and
    exprPathFromVarRootV1(sourceVar, rhs, relativePath) and
    path = joinPathV1(sourcePath, relativePath) and
    callDepth = sourceCallDepth and
    aliasHops = sourceAliasHops + 1
  )
}

predicate trackedHolderVariableV1(
  Function holder,
  Variable root,
  Function f,
  Variable v,
  string path,
  int callDepth,
  int aliasHops
) {
  rootBelongsToHolderV1(root, holder) and
  trackedHolderVariableCoreV1(holder, root, f, v, path, callDepth, aliasHops)
}

predicate holderExprPathV1(
  Function holder,
  Variable root,
  Function f,
  Expr e,
  string fullPath
) {
  exists(
    Variable v, string variablePath, string relativePath,
    int callDepth, int aliasHops
  |
    trackedHolderVariableV1(
      holder, root, f, v, variablePath, callDepth, aliasHops
    ) and
    exprPathFromVarRootV1(v, e, relativePath) and
    fullPath = joinPathV1(variablePath, relativePath)
  )
}

predicate registrationRootMappingV1(
  Function holder,
  IrqRegistrationCallV1 registration,
  Variable root,
  string dataPath,
  int holderToRegistrationDepth
) {
  inTargetFunctionV1(holder) and
  inTargetFunctionV1(registration.getEnclosingFunction()) and
  rootBelongsToHolderV1(root, holder) and
  holderReachesRegistrationOwnerV1(holder, registration, holderToRegistrationDepth) and
  holderExprPathV1(
    holder, root, registration.getEnclosingFunction(),
    irqDevIdArgV1(registration), dataPath
  )
}

predicate freeRootMappingV1(
  Function holder,
  FreeLikeSink sink,
  Variable root,
  string freePath,
  int holderToFreeDepth
) {
  inTargetFunctionV1(holder) and
  inTargetFunctionV1(sinkOwner(sink)) and
  rootBelongsToHolderV1(root, holder) and
  holderReachesFreeOwnerV1(holder, sink, holderToFreeDepth) and
  holderExprPathV1(
    holder, root, sinkOwner(sink), freeObjectArgV1(sink), freePath
  )
}

/**
 * 跨生命周期函数的根对象兼容关系。
 *
 * 精确实体相等仍是最强证据；probe/remove 等独立入口中的参数或局部变量
 * 无法成为同一个 QL Variable，因此允许相同的非通用静态类型作为对象键。
 */
predicate lifecycleRootsCompatibleV1(Variable registrationRoot, Variable freeRoot) {
  registrationRoot = freeRoot
  or
  registrationRoot.getName() = freeRoot.getName() and
  registrationRoot.getType() = freeRoot.getType() and
  not registrationRoot.getType().toString() = "void *" and
  not registrationRoot.getType().toString() = "const void *" and
  not registrationRoot.getType().toString() = "char *" and
  not registrationRoot.getType().toString() = "unsigned char *"
}

/** 注册侧和 free 侧可来自不同生命周期入口，但必须解释为兼容根对象。 */
predicate lifecycleRootMappingV1(
  FreeLikeSink sink,
  Function holder,
  IrqRegistrationCallV1 registration,
  Variable root,
  string dataPath,
  string freePath,
  int holderToRegistrationDepth,
  int holderToFreeDepth
) {
  exists(Function freeHolder, Variable freeRoot |
    registrationRootMappingV1(
      holder, registration, root, dataPath, holderToRegistrationDepth
    ) and
    freeRootMappingV1(
      freeHolder, sink, freeRoot, freePath, holderToFreeDepth
    ) and
    lifecycleRootsCompatibleV1(root, freeRoot)
  )
}

/**
 * 将生命周期映射投影为 registration + dataPath。
 *
 * IRQ 侧传播不依赖具体 free、holder 或 root；先投影掉这些维度，避免它们
 * 进入递归种子的关系键。lifecycleRootMappingV1 保持原有语义：只要同一个
 * registration/dataPath 存在一个配对 free 即可产生种子。
 */
bindingset[registration]
predicate registrationHasLifecycleFreePathV1(
  IrqRegistrationCallV1 registration,
  string dataPath
) {
  exists(
    FreeLikeSink sink, Function holder, Variable root, string freePath,
    int holderToRegistrationDepth, int holderToFreeDepth
  |
    lifecycleRootMappingV1(
      sink, holder, registration, root, dataPath, freePath,
      holderToRegistrationDepth, holderToFreeDepth
    )
  )
}

/** IRQ 侧递归的有限种子，不携带 sink/holder/root。 */
bindingset[registration]
predicate lifecycleIrqSeedV1(
  IrqRegistrationCallV1 registration,
  Function entry,
  string seedDataPath
) {
  registrationHasLifecycleFreePathV1(registration, seedDataPath) and
  exists(string handlerKind |
    irqEntryFunctionV1(registration, entry, handlerKind)
  )
}

/** IRQ handler/thread_fn 侧有限传播。 */
predicate trackedIrqVariableCoreV1(
  IrqRegistrationCallV1 registration,
  Function entry,
  string seedDataPath,
  Function f,
  Variable v,
  string path,
  int callDepth,
  int aliasHops
) {
  lifecycleIrqSeedV1(registration, entry, seedDataPath) and
  f = entry and
  v = irqEntryDataParamV1(registration, entry) and
  path = seedDataPath and
  callDepth = 0 and
  aliasHops = 0
  or
  exists(
    Function caller, Function callee, FunctionCall call,
    Variable sourceVar, string sourcePath, string relativePath,
    int sourceCallDepth, int sourceAliasHops, int i
  |
    trackedIrqVariableCoreV1(
      registration, entry, seedDataPath, caller, sourceVar, sourcePath,
      sourceCallDepth, sourceAliasHops
    ) and
    sourceCallDepth < maxIrqDataFlowDepth() and
    allowedIrqPropagationFunctionV1(callee) and
    caller.calls(callee, call) and
    exprPathFromVarRootV1(sourceVar, call.getArgument(i), relativePath) and
    f = callee and
    v = callee.getParameter(i) and
    path = joinPathV1(sourcePath, relativePath) and
    callDepth = sourceCallDepth + 1 and
    aliasHops = sourceAliasHops
  )
  or
  exists(
    LocalVariable local, Initializer init0, Expr rhs,
    Variable sourceVar, string sourcePath, string relativePath,
    int sourceCallDepth, int sourceAliasHops
  |
    local = v and
    local.getFunction() = f and
    init0 = local.getInitializer() and
    rhs = init0.getExpr() and
    trackedIrqVariableCoreV1(
      registration, entry, seedDataPath, f, sourceVar, sourcePath,
      sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxIrqLocalAliasHops() and
    (
      exprPathFromVarRootV1(sourceVar, rhs, relativePath) and
      path = joinPathV1(sourcePath, relativePath)
      or
      relativePath = "" and
      containerPathFromTrackedVariableV1(sourceVar, sourcePath, f, rhs, path)
    ) and
    callDepth = sourceCallDepth and
    aliasHops = sourceAliasHops + 1
  )
  or
  exists(
    LocalVariable local, AssignExpr assignment, VariableAccess lhs, Expr rhs,
    Variable sourceVar, string sourcePath, string relativePath,
    int sourceCallDepth, int sourceAliasHops
  |
    local = v and
    local.getFunction() = f and
    assignment.getEnclosingFunction() = f and
    lhs = stripExprV1(assignment.getLValue()) and
    lhs.getTarget() = local and
    rhs = assignment.getRValue() and
    trackedIrqVariableCoreV1(
      registration, entry, seedDataPath, f, sourceVar, sourcePath,
      sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxIrqLocalAliasHops() and
    (
      exprPathFromVarRootV1(sourceVar, rhs, relativePath) and
      path = joinPathV1(sourcePath, relativePath)
      or
      relativePath = "" and
      containerPathFromTrackedVariableV1(sourceVar, sourcePath, f, rhs, path)
    ) and
    callDepth = sourceCallDepth and
    aliasHops = sourceAliasHops + 1
  )
}

bindingset[registration, entry, seedDataPath, f, e]
predicate irqExprPathV1(
  IrqRegistrationCallV1 registration,
  Function entry,
  string seedDataPath,
  Function f,
  Expr e,
  string fullPath
) {
  exists(
    Variable v, string variablePath, string relativePath,
    int callDepth, int aliasHops
  |
    trackedIrqVariableCoreV1(
      registration, entry, seedDataPath, f, v, variablePath,
      callDepth, aliasHops
    ) and
    exprPathFromVarRootV1(v, e, relativePath) and
    fullPath = joinPathV1(variablePath, relativePath)
  )
  or
  exists(
    Variable v, string variablePath,
    int callDepth, int aliasHops
  |
    trackedIrqVariableCoreV1(
      registration, entry, seedDataPath, f, v, variablePath,
      callDepth, aliasHops
    ) and
    containerPathFromTrackedVariableV1(v, variablePath, f, e, fullPath)
  )
}

