/**
 * kthread_reachable_data_access_v7.qll
 *
 * v4.1 核心变化：
 * 1. holder 可有限深度到达 start owner 和 free owner；
 * 2. holder 公共根支持 Parameter | LocalVariable；
 * 3. holder/thread 跨函数传播均有限深度；
 * 4. 线程递归核心只依赖 (start, seedDataPath)，不再在每个递归状态中
 *    重算 startDataOnHolderRoot，消除 v3.1 的笛卡尔放大；
 * 5. 线程传播关系不携带 holder/root/sink，多个生命周期候选可复用同一
 *    start + seed path 的线程侧传播结果；
 * 6. 调用链中间节点与线程 helper 受目录范围约束；
 * 7. 递归谓词不再使用 bindingset，改由有限基础种子关系进行范围约束，
 *    修复 “recursive cycle of relations that must be inlined” 编译错误。
 */

import cpp
import find_before
import kthread_fast_recall_config_v4
import container_of_kernel_v1

class KthreadStartCallV4 extends FunctionCall {
  KthreadStartCallV4() {
    this.getTarget().hasName("__kthread_run") or
    this.getTarget().hasName("kthread_run") or
    this.getTarget().hasName("kthread_create") or
    this.getTarget().hasName("kthread_create_on_node") or
    this.getTarget().hasName("kthread_create_on_cpu") or
    this.getTarget().hasName("kthread_run_on_cpu") or
    this.getTarget().hasName("user_mode_thread") or
    this.getTarget().hasName("create_io_thread")
  }
}

/** 底层 create 调用是否来自会立即唤醒线程的 kthread_run 类宏。 */
predicate expandedFromRunMacroV4(KthreadStartCallV4 start) {
  exists(MacroInvocation mi |
    mi.getAnExpandedElement() = start and
    (
      mi.getMacroName() = "kthread_run" or
      mi.getMacroName() = "kthread_run_on_cpu"
    )
  )
}

/** 输出源码层 start API，避免只看到宏展开后的底层 target。 */
string kthreadSourceStartApiV4(KthreadStartCallV4 start) {
  exists(MacroInvocation mi |
    mi.getAnExpandedElement() = start and
    mi.getMacroName() = "kthread_run" and
    result = "kthread_run"
  )
  or
  not exists(MacroInvocation mi |
    mi.getAnExpandedElement() = start and
    mi.getMacroName() = "kthread_run"
  ) and
  exists(MacroInvocation mi |
    mi.getAnExpandedElement() = start and
    mi.getMacroName() = "kthread_run_on_cpu" and
    result = "kthread_run_on_cpu"
  )
  or
  not expandedFromRunMacroV4(start) and
  result = start.getTarget().getName()
}

string kthreadStartKindV4(KthreadStartCallV4 start) {
  expandedFromRunMacroV4(start) and
  result = "run_and_wake"
  or
  not expandedFromRunMacroV4(start) and
  (
    start.getTarget().hasName("kthread_create") or
    start.getTarget().hasName("kthread_create_on_node") or
    start.getTarget().hasName("kthread_create_on_cpu")
  ) and
  result = "create_stopped"
  or
  not expandedFromRunMacroV4(start) and
  (
    start.getTarget().hasName("__kthread_run") or
    start.getTarget().hasName("kthread_run") or
    start.getTarget().hasName("kthread_run_on_cpu") or
    start.getTarget().hasName("user_mode_thread") or
    start.getTarget().hasName("create_io_thread")
  ) and
  result = "run_or_immediate_start"
}

/** 确定性剥离：只返回最内层括号/cast/取地址操作数。 */
Expr stripExprV4(Expr e) {
  exists(ParenthesisExpr p |
    e = p and result = stripExprV4(p.getExpr())
  )
  or
  exists(Cast c |
    e = c and result = stripExprV4(c.getExpr())
  )
  or
  exists(AddressOfExpr a |
    e = a and result = stripExprV4(a.getOperand())
  )
  or
  not e instanceof ParenthesisExpr and
  not e instanceof Cast and
  not e instanceof AddressOfExpr and
  result = e
}

bindingset[a, b]
string joinPathV4(string a, string b) {
  a = "" and result = b
  or
  b = "" and result = a
  or
  a != "" and b != "" and result = a + "." + b
}

bindingset[prefix, full]
predicate pathIsSameOrDescendantV4(string prefix, string full) {
  prefix = ""
  or
  full = prefix
  or
  exists(string suffix |
    suffix != "" and full = prefix + "." + suffix
  )
}

predicate exprPathFromVarRootV4(Variable v, Expr e, string path) {
  exists(VariableAccess va |
    stripExprV4(e) = va and
    va.getTarget() = v and
    path = ""
  )
  or
  exists(FieldAccess fa, string basePath |
    stripExprV4(e) = fa and
    exprPathFromVarRootV4(v, fa.getQualifier(), basePath) and
    path = joinPathV4(basePath, fa.getTarget().getName())
  )
}

bindingset[txt]
private predicate exprMatchesContainerArgTextV4(Expr e, string txt) {
  e.toString() = txt or stripExprV4(e).toString() = txt
}

/**
 * Recover P from a container-like result when the macro pointer argument is
 * already tracked as P.member. This preserves the original common-root
 * container_of/list_entry/hlist_entry/rb_entry/from_timer semantics while the
 * surrounding propagation remains bounded.
 */
bindingset[sourceVar, sourcePath, f, containerExpr]
private predicate containerPathFromTrackedVariableV4(
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
    stripExprV4(containerExpr) = stripExprV4(macroResult) and
    macroResult.getEnclosingFunction() = f and
    pointerArg.getEnclosingFunction() = f and
    containerLikePtrArgText(macro, pointerText) and
    containerLikeMemberText(macro, member) and
    exprMatchesContainerArgTextV4(pointerArg, pointerText) and
    exprPathFromVarRootV4(sourceVar, pointerArg, relativePointerPath) and
    pointerFullPath = joinPathV4(sourcePath, relativePointerPath) and
    stripContainerMember(pointerFullPath, member, fullPath)
  )
}

predicate rootBelongsToHolderV4(Variable root, Function holder) {
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

string holderRootKindV4(Variable root) {
  root instanceof Parameter and result = "parameter"
  or
  root instanceof LocalVariable and result = "local_variable"
  or
  root instanceof GlobalVariable and result = "global_variable"
}

/** 精确深度的普通直接调用可达关系，并限制中间函数范围。 */
predicate directCallReachableAtDepthV4(Function src, Function dst, int depth) {
  depth = 0 and src = dst
  or
  exists(Function next, int previousDepth |
    previousDepth >= 0 and
    previousDepth < maxBoundedCallDepth() and
    depth = previousDepth + 1 and
    allowedCallBridgeFunctionV4(src) and
    allowedCallBridgeFunctionV4(next) and
    directCaller(src, next) and
    directCallReachableAtDepthV4(next, dst, previousDepth)
  )
}

predicate holderReachesStartOwnerV4(
  Function holder, KthreadStartCallV4 start, int depth
) {
  depth >= 0 and
  depth <= maxHolderToStartCallDepth() and
  directCallReachableAtDepthV4(holder, start.getEnclosingFunction(), depth)
}

predicate holderReachesFreeOwnerV4(
  Function holder, FreeLikeSink sink, int depth
) {
  depth >= 0 and
  depth <= maxHolderToFreeCallDepth() and
  directCallReachableAtDepthV4(holder, sinkOwner(sink), depth)
}

Function threadEntryV4(KthreadStartCallV4 start) {
  exists(FunctionAccess fa |
    fa = stripExprV4(start.getArgument(0)) and
    result = fa.getTarget()
  )
}

Expr threadDataArgV4(KthreadStartCallV4 start) {
  result = stripExprV4(start.getArgument(1))
}

Parameter entryDataParamV4(KthreadStartCallV4 start) {
  result = threadEntryV4(start).getParameter(0)
}

Expr freeObjectArgV4(FreeLikeSink sink) {
  result = stripExprV4(sink.getArgument(sink.getFreedArgumentIndex()))
}

/**
 * holder 侧传播核心。holder/root 是绑定输入，避免为同一递归状态重新枚举根。
 */
predicate trackedHolderVariableCoreV4(
  Function holder,
  Variable root,
  Function f,
  Variable v,
  string path,
  int callDepth,
  int aliasHops
) {
  rootBelongsToHolderV4(root, holder) and
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
    trackedHolderVariableCoreV4(
      holder, root, caller, sourceVar, sourcePath, sourceCallDepth, sourceAliasHops
    ) and
    sourceCallDepth < maxHolderDataFlowDepth() and
    allowedCallBridgeFunctionV4(callee) and
    caller.calls(callee, call) and
    exprPathFromVarRootV4(sourceVar, call.getArgument(i), relativePath) and
    f = callee and
    v = callee.getParameter(i) and
    path = joinPathV4(sourcePath, relativePath) and
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
    trackedHolderVariableCoreV4(
      holder, root, f, sourceVar, sourcePath, sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxHolderLocalAliasHops() and
    (
      exprPathFromVarRootV4(sourceVar, rhs, relativePath) and
      path = joinPathV4(sourcePath, relativePath)
      or
      relativePath = "" and
      containerPathFromTrackedVariableV4(sourceVar, sourcePath, f, rhs, path)
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
    lhs = stripExprV4(assignment.getLValue()) and
    lhs.getTarget() = local and
    rhs = assignment.getRValue() and
    trackedHolderVariableCoreV4(
      holder, root, f, sourceVar, sourcePath, sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxHolderLocalAliasHops() and
    (
      exprPathFromVarRootV4(sourceVar, rhs, relativePath) and
      path = joinPathV4(sourcePath, relativePath)
      or
      relativePath = "" and
      containerPathFromTrackedVariableV4(sourceVar, sourcePath, f, rhs, path)
    ) and
    callDepth = sourceCallDepth and
    aliasHops = sourceAliasHops + 1
  )
}

predicate trackedHolderVariableV4(
  Function holder,
  Variable root,
  Function f,
  Variable v,
  string path,
  int callDepth,
  int aliasHops
) {
  rootBelongsToHolderV4(root, holder) and
  trackedHolderVariableCoreV4(holder, root, f, v, path, callDepth, aliasHops)
}

predicate holderExprPathV4(
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
    trackedHolderVariableV4(
      holder, root, f, v, variablePath, callDepth, aliasHops
    ) and
    exprPathFromVarRootV4(v, e, relativePath) and
    fullPath = joinPathV4(variablePath, relativePath)
  )
  or
  exists(
    Variable v, string variablePath,
    int callDepth, int aliasHops
  |
    trackedHolderVariableV4(
      holder, root, f, v, variablePath, callDepth, aliasHops
    ) and
    containerPathFromTrackedVariableV4(v, variablePath, f, e, fullPath)
  )
}

predicate startRootMappingV4(
  Function holder,
  KthreadStartCallV4 start,
  Variable root,
  string dataPath,
  int holderToStartDepth
) {
  inTargetFunctionV4(holder) and
  inTargetFunctionV4(start.getEnclosingFunction()) and
  rootBelongsToHolderV4(root, holder) and
  holderReachesStartOwnerV4(holder, start, holderToStartDepth) and
  holderExprPathV4(
    holder, root, start.getEnclosingFunction(), threadDataArgV4(start), dataPath
  )
}

predicate freeRootMappingV4(
  Function holder,
  FreeLikeSink sink,
  Variable root,
  string freePath,
  int holderToFreeDepth
) {
  inTargetFunctionV4(holder) and
  inTargetFunctionV4(sinkOwner(sink)) and
  rootBelongsToHolderV4(root, holder) and
  holderReachesFreeOwnerV4(holder, sink, holderToFreeDepth) and
  holderExprPathV4(
    holder, root, sinkOwner(sink), freeObjectArgV4(sink), freePath
  )
}

/**
 * 精确实体相等优先；独立生命周期入口中的根变量允许按相同的非通用
 * 静态类型对应，覆盖 start/probe 与 stop/remove/free 分离的情况。
 */
predicate lifecycleRootsCompatibleV4(Variable startRoot, Variable freeRoot) {
  startRoot = freeRoot
  or
  startRoot.getFile() = freeRoot.getFile() and
  startRoot.getName() = freeRoot.getName() and
  startRoot.getType() = freeRoot.getType() and
  not startRoot.getType().toString() = "void *" and
  not startRoot.getType().toString() = "const void *" and
  not startRoot.getType().toString() = "char *" and
  not startRoot.getType().toString() = "unsigned char *"
}

/** start 侧和 free 侧可来自不同生命周期入口，但根对象必须兼容。 */
predicate lifecycleRootMappingV4(
  FreeLikeSink sink,
  Function holder,
  KthreadStartCallV4 start,
  Variable root,
  string dataPath,
  string freePath,
  int holderToStartDepth,
  int holderToFreeDepth
) {
  exists(Function freeHolder, Variable freeRoot |
    startRootMappingV4(
      holder, start, root, dataPath, holderToStartDepth
    ) and
    freeRootMappingV4(
      freeHolder, sink, freeRoot, freePath, holderToFreeDepth
    ) and
    lifecycleRootsCompatibleV4(root, freeRoot)
  )
}

/**
 * 为线程递归提供有限、已闭合的种子集合。
 *
 * 这个关系只依赖 holder 侧生命周期映射，不依赖线程侧递归，因此不会
 * 形成递归环。seedDataPath 在这里由实际 start/free 公共根映射产生，
 * 避免在递归谓词上使用 bindingset（CodeQL 不允许需要内联的递归环）。
 */
predicate lifecycleThreadSeedV4(
  KthreadStartCallV4 start,
  string seedDataPath
) {
  exists(
    FreeLikeSink sink, Function holder, Variable root, string freePath,
    int holderToStartDepth, int holderToFreeDepth
  |
    lifecycleRootMappingV4(
      sink, holder, start, root, seedDataPath, freePath,
      holderToStartDepth, holderToFreeDepth
    )
  )
}

/**
 * 线程侧传播核心。
 *
 * 递归状态只携带 start + seedDataPath，不携带 holder/root/sink。
 * seed 仅在基础分支中由 lifecycleThreadSeedV4 产生；递归分支只扩展
 * 已生成的有限状态，因此不会重复执行 holder 侧传播。
 */
predicate trackedThreadVariableCoreV4(
  KthreadStartCallV4 start,
  string seedDataPath,
  Function f,
  Variable v,
  string path,
  int callDepth,
  int aliasHops
) {
  lifecycleThreadSeedV4(start, seedDataPath) and
  f = threadEntryV4(start) and
  v = entryDataParamV4(start) and
  path = seedDataPath and
  callDepth = 0 and
  aliasHops = 0
  or
  exists(
    Function caller, Function callee, FunctionCall call,
    Variable sourceVar, string sourcePath, string relativePath,
    int sourceCallDepth, int sourceAliasHops, int i
  |
    trackedThreadVariableCoreV4(
      start, seedDataPath, caller, sourceVar, sourcePath,
      sourceCallDepth, sourceAliasHops
    ) and
    sourceCallDepth < maxThreadDataFlowDepth() and
    allowedThreadPropagationFunctionV4(callee) and
    caller.calls(callee, call) and
    exprPathFromVarRootV4(sourceVar, call.getArgument(i), relativePath) and
    f = callee and
    v = callee.getParameter(i) and
    path = joinPathV4(sourcePath, relativePath) and
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
    trackedThreadVariableCoreV4(
      start, seedDataPath, f, sourceVar, sourcePath,
      sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxThreadLocalAliasHops() and
    (
      exprPathFromVarRootV4(sourceVar, rhs, relativePath) and
      path = joinPathV4(sourcePath, relativePath)
      or
      relativePath = "" and
      containerPathFromTrackedVariableV4(sourceVar, sourcePath, f, rhs, path)
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
    lhs = stripExprV4(assignment.getLValue()) and
    lhs.getTarget() = local and
    rhs = assignment.getRValue() and
    trackedThreadVariableCoreV4(
      start, seedDataPath, f, sourceVar, sourcePath,
      sourceCallDepth, sourceAliasHops
    ) and
    sourceVar != local and
    sourceAliasHops < maxThreadLocalAliasHops() and
    (
      exprPathFromVarRootV4(sourceVar, rhs, relativePath) and
      path = joinPathV4(sourcePath, relativePath)
      or
      relativePath = "" and
      containerPathFromTrackedVariableV4(sourceVar, sourcePath, f, rhs, path)
    ) and
    callDepth = sourceCallDepth and
    aliasHops = sourceAliasHops + 1
  )
}

bindingset[start, seedDataPath, f, e]
predicate threadExprPathV4(
  KthreadStartCallV4 start,
  string seedDataPath,
  Function f,
  Expr e,
  string fullPath
) {
  exists(
    Variable v, string variablePath, string relativePath,
    int callDepth, int aliasHops
  |
    trackedThreadVariableCoreV4(
      start, seedDataPath, f, v, variablePath, callDepth, aliasHops
    ) and
    exprPathFromVarRootV4(v, e, relativePath) and
    fullPath = joinPathV4(variablePath, relativePath)
  )
  or
  exists(
    Variable v, string variablePath,
    int callDepth, int aliasHops
  |
    trackedThreadVariableCoreV4(
      start, seedDataPath, f, v, variablePath, callDepth, aliasHops
    ) and
    containerPathFromTrackedVariableV4(v, variablePath, f, e, fullPath)
  )
}

