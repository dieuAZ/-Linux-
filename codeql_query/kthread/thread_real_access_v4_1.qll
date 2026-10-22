/**
 * thread_real_access_v4_1.qll
 *
 * - 线程传播只使用 start + seedDataPath，避免生命周期维度进入递归关系；
 * - obj->arr[0] 只保留 array_access；
 * - *obj->ptr 只保留 deref_access；
 * - 已知内存 API 参数只保留 mem_api_arg_use；
 * - 多层字段只保留最外层字段。
 */

import cpp
import kthread_reachable_data_access_v7

bindingset[prefix, full]
predicate pathIsStrictDescendantForRealUseV4(string prefix, string full) {
  prefix = "" and full != ""
  or
  exists(string suffix |
    suffix != "" and full = prefix + "." + suffix
  )
}

predicate notPureAddressTakingV4(Expr e) {
  not exists(AddressOfExpr a |
    stripExprV4(a.getOperand()) = stripExprV4(e)
  )
}

predicate notQualifierOfAnotherFieldAccessV4(Expr e) {
  not exists(FieldAccess outer |
    stripExprV4(outer.getQualifier()) = stripExprV4(e)
  )
}

predicate memoryApiArgUseV4(FunctionCall call, int argIndex, string useKind) {
  (
    call.getTarget().hasName("memcpy") or
    call.getTarget().hasName("memmove") or
    call.getTarget().hasName("memcmp") or
    call.getTarget().hasName("memcpy_toio") or
    call.getTarget().hasName("memcpy_fromio")
  ) and
  (argIndex = 0 or argIndex = 1) and
  useKind = "mem_api_arg_use"
  or
  (
    call.getTarget().hasName("memset") or
    call.getTarget().hasName("memzero_explicit")
  ) and
  argIndex = 0 and
  useKind = "mem_api_arg_use"
  or
  (
    call.getTarget().hasName("strlen") or
    call.getTarget().hasName("strnlen") or
    call.getTarget().hasName("strchr") or
    call.getTarget().hasName("strrchr") or
    call.getTarget().hasName("strnchr") or
    call.getTarget().hasName("memchr")
  ) and
  argIndex = 0 and
  useKind = "mem_api_arg_use"
  or
  (
    call.getTarget().hasName("strcmp") or
    call.getTarget().hasName("strncmp")
  ) and
  (argIndex = 0 or argIndex = 1) and
  useKind = "mem_api_arg_use"
  or
  (
    call.getTarget().hasName("strcpy") or
    call.getTarget().hasName("strncpy") or
    call.getTarget().hasName("strscpy") or
    call.getTarget().hasName("strscpy_pad") or
    call.getTarget().hasName("strlcpy") or
    call.getTarget().hasName("strcat") or
    call.getTarget().hasName("strncat")
  ) and
  (argIndex = 0 or argIndex = 1) and
  useKind = "mem_api_arg_use"
  or
  call.getTarget().hasName("copy_to_user") and
  argIndex = 1 and
  useKind = "mem_api_arg_use"
  or
  call.getTarget().hasName("copy_from_user") and
  argIndex = 0 and
  useKind = "mem_api_arg_use"
  or
  (
    call.getTarget().hasName("kmemdup") or
    call.getTarget().hasName("kmemdup_nul")
  ) and
  argIndex = 0 and
  useKind = "mem_api_arg_use"
}

predicate isArrayBaseV4(Expr e) {
  exists(ArrayExpr ae |
    stripExprV4(ae.getArrayBase()) = stripExprV4(e)
  )
}

predicate isDereferenceOperandV4(Expr e) {
  exists(PointerDereferenceExpr de |
    stripExprV4(de.getOperand()) = stripExprV4(e)
  )
}

predicate isDirectKnownMemoryApiArgumentV4(Expr e) {
  exists(FunctionCall call, int i, string kind |
    memoryApiArgUseV4(call, i, kind) and
    stripExprV4(call.getArgument(i)) = stripExprV4(e)
  )
}

predicate fieldIsCoveredByMoreSpecificUseV4(FieldAccess fa) {
  isArrayBaseV4(fa)
  or
  isDereferenceOperandV4(fa)
  or
  isDirectKnownMemoryApiArgumentV4(fa)
}

bindingset[start, seedDataPath]
predicate threadSideRealAccessV4(
  KthreadStartCallV4 start,
  string seedDataPath,
  Function f,
  Expr access,
  string accessPath,
  string useKind
) {
  allowedThreadPropagationFunctionV4(f) and
  (
    exists(FieldAccess fa |
      access = fa and
      fa.getEnclosingFunction() = f and
      threadExprPathV4(start, seedDataPath, f, fa, accessPath) and
      notPureAddressTakingV4(fa) and
      notQualifierOfAnotherFieldAccessV4(fa) and
      not fieldIsCoveredByMoreSpecificUseV4(fa) and
      (fa.isRValue() or fa.isModified() or fa.isUsedAsLValue()) and
      useKind = "field_access"
    )
    or
    exists(PointerDereferenceExpr de |
      access = de and
      de.getEnclosingFunction() = f and
      threadExprPathV4(start, seedDataPath, f, de.getOperand(), accessPath) and
      notPureAddressTakingV4(de) and
      useKind = "deref_access"
    )
    or
    exists(ArrayExpr ae |
      access = ae and
      ae.getEnclosingFunction() = f and
      threadExprPathV4(start, seedDataPath, f, ae.getArrayBase(), accessPath) and
      notPureAddressTakingV4(ae) and
      (ae.hasLValueToRValueConversion() or ae.isModified()) and
      useKind = "array_access"
    )
    or
    exists(FunctionCall call, int i, Expr arg |
      call.getEnclosingFunction() = f and
      memoryApiArgUseV4(call, i, useKind) and
      arg = stripExprV4(call.getArgument(i)) and
      access = call and
      threadExprPathV4(start, seedDataPath, f, arg, accessPath)
    )
  )
}

bindingset[freePath, accessPath, useKind]
predicate realUseHitsFreedPathV4(
  string freePath, string accessPath, string useKind
) {
  useKind = "field_access" and
  accessPath != "" and
  pathIsSameOrDescendantV4(freePath, accessPath)
  or
  useKind != "field_access" and
  pathIsSameOrDescendantV4(freePath, accessPath)
}

/** 一个具体 use-site 级别的候选证据。 */
predicate kthreadCandidateAccessV4(
  FreeLikeSink sink,
  Function holder,
  KthreadStartCallV4 start,
  Variable holderRoot,
  Function threadFunc,
  Expr access,
  string dataPath,
  string freePath,
  string accessPath,
  string useKind,
  int holderToStartDepth,
  int holderToFreeDepth
) {
  lifecycleRootMappingV4(
    sink, holder, start, holderRoot, dataPath, freePath,
    holderToStartDepth, holderToFreeDepth
  ) and
  threadSideRealAccessV4(
    start, dataPath, threadFunc, access, accessPath, useKind
  ) and
  realUseHitsFreedPathV4(freePath, accessPath, useKind)
}

/** 候选是否至少存在一个真实 thread-side use。 */
predicate kthreadCandidateExistsV4(
  FreeLikeSink sink,
  Function holder,
  KthreadStartCallV4 start,
  Variable holderRoot,
  string dataPath,
  string freePath,
  int holderToStartDepth,
  int holderToFreeDepth
) {
  lifecycleRootMappingV4(
    sink, holder, start, holderRoot, dataPath, freePath,
    holderToStartDepth, holderToFreeDepth
  ) and
  exists(Function threadFunc, Expr access, string accessPath, string useKind |
    threadSideRealAccessV4(
      start, dataPath, threadFunc, access, accessPath, useKind
    ) and
    realUseHitsFreedPathV4(freePath, accessPath, useKind)
  )
}


