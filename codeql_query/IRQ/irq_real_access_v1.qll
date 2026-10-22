/**
 * irq_real_access_v1.qll
 *
 * IRQ 回调侧真实 use 过滤：
 * - 多层字段只保留最外层字段；
 * - obj->arr[i] 只保留 array_access；
 * - *obj->ptr 只保留 deref_access；
 * - 已知内存 API 参数只保留 mem_api_arg_use；
 * - 单纯取地址不算真实访问。
 */

import cpp
import irq_reachable_data_access_v1

bindingset[prefix, full]
predicate pathIsStrictDescendantForRealUseV1(string prefix, string full) {
  prefix = "" and full != ""
  or
  exists(string suffix |
    suffix != "" and full = prefix + "." + suffix
  )
}

predicate notPureAddressTakingV1(Expr e) {
  not exists(AddressOfExpr a |
    stripExprV1(a.getOperand()) = stripExprV1(e)
  )
}

predicate notQualifierOfAnotherFieldAccessV1(Expr e) {
  not exists(FieldAccess outer |
    stripExprV1(outer.getQualifier()) = stripExprV1(e)
  )
}

predicate memoryApiArgUseV1(FunctionCall call, int argIndex, string useKind) {
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

predicate isArrayBaseV1(Expr e) {
  exists(ArrayExpr ae |
    stripExprV1(ae.getArrayBase()) = stripExprV1(e)
  )
}

predicate isDereferenceOperandV1(Expr e) {
  exists(PointerDereferenceExpr de |
    stripExprV1(de.getOperand()) = stripExprV1(e)
  )
}

predicate isDirectKnownMemoryApiArgumentV1(Expr e) {
  exists(FunctionCall call, int i, string kind |
    memoryApiArgUseV1(call, i, kind) and
    stripExprV1(call.getArgument(i)) = stripExprV1(e)
  )
}

predicate fieldIsCoveredByMoreSpecificUseV1(FieldAccess fa) {
  isArrayBaseV1(fa)
  or
  isDereferenceOperandV1(fa)
  or
  isDirectKnownMemoryApiArgumentV1(fa)
}

bindingset[registration, entry, seedDataPath]
predicate irqSideRealAccessV1(
  IrqRegistrationCallV1 registration,
  Function entry,
  string seedDataPath,
  Function f,
  Expr access,
  string accessPath,
  string useKind
) {
  allowedIrqPropagationFunctionV1(f) and
  (
    exists(FieldAccess fa |
      access = fa and
      fa.getEnclosingFunction() = f and
      irqExprPathV1(registration, entry, seedDataPath, f, fa, accessPath) and
      notPureAddressTakingV1(fa) and
      notQualifierOfAnotherFieldAccessV1(fa) and
      not fieldIsCoveredByMoreSpecificUseV1(fa) and
      (fa.isRValue() or fa.isModified() or fa.isUsedAsLValue()) and
      useKind = "field_access"
    )
    or
    exists(PointerDereferenceExpr de |
      access = de and
      de.getEnclosingFunction() = f and
      irqExprPathV1(
        registration, entry, seedDataPath, f, de.getOperand(), accessPath
      ) and
      notPureAddressTakingV1(de) and
      useKind = "deref_access"
    )
    or
    exists(ArrayExpr ae |
      access = ae and
      ae.getEnclosingFunction() = f and
      irqExprPathV1(
        registration, entry, seedDataPath, f, ae.getArrayBase(), accessPath
      ) and
      notPureAddressTakingV1(ae) and
      (ae.hasLValueToRValueConversion() or ae.isModified()) and
      useKind = "array_access"
    )
    or
    exists(FunctionCall call, int i, Expr arg |
      call.getEnclosingFunction() = f and
      memoryApiArgUseV1(call, i, useKind) and
      arg = stripExprV1(call.getArgument(i)) and
      access = call and
      irqExprPathV1(
        registration, entry, seedDataPath, f, arg, accessPath
      )
    )
  )
}

bindingset[freePath, accessPath, useKind]
predicate realUseHitsFreedPathV1(
  string freePath, string accessPath, string useKind
) {
  useKind = "field_access" and
  accessPath != "" and
  pathIsSameOrDescendantV1(freePath, accessPath)
  or
  useKind != "field_access" and
  pathIsSameOrDescendantV1(freePath, accessPath)
}

predicate irqCandidateAccessV1(
  FreeLikeSink sink,
  Function holder,
  IrqRegistrationCallV1 registration,
  Variable holderRoot,
  Function entry,
  string handlerKind,
  Function irqFunc,
  Expr access,
  string dataPath,
  string freePath,
  string accessPath,
  string useKind,
  int holderToRegistrationDepth,
  int holderToFreeDepth
) {
  lifecycleRootMappingV1(
    sink, holder, registration, holderRoot, dataPath, freePath,
    holderToRegistrationDepth, holderToFreeDepth
  ) and
  irqEntryFunctionV1(registration, entry, handlerKind) and
  irqSideRealAccessV1(
    registration, entry, dataPath, irqFunc, access, accessPath, useKind
  ) and
  realUseHitsFreedPathV1(freePath, accessPath, useKind)
}

predicate irqCandidateExistsV1(
  FreeLikeSink sink,
  Function holder,
  IrqRegistrationCallV1 registration,
  Variable holderRoot,
  Function entry,
  string handlerKind,
  string dataPath,
  string freePath,
  int holderToRegistrationDepth,
  int holderToFreeDepth
) {
  lifecycleRootMappingV1(
    sink, holder, registration, holderRoot, dataPath, freePath,
    holderToRegistrationDepth, holderToFreeDepth
  ) and
  irqEntryFunctionV1(registration, entry, handlerKind) and
  exists(Function irqFunc, Expr access, string accessPath, string useKind |
    irqSideRealAccessV1(
      registration, entry, dataPath, irqFunc, access, accessPath, useKind
    ) and
    realUseHitsFreedPathV1(freePath, accessPath, useKind)
  )
}


