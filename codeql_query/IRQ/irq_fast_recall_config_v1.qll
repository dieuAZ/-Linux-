/**
 * irq_fast_recall_config_v1.qll
 *
 * IRQ 高召回查询的范围与深度配置。
 * 扫描与传播范围完全由当前 CodeQL 数据库决定。
 */

import cpp

/** holder 到 IRQ 注册点/free 点所属函数的普通直接调用深度。 */
int maxHolderToRegistrationCallDepth() { result = 4 }
int maxHolderToFreeCallDepth() { result = 4 }

/** holder 侧和 IRQ 回调侧的实参到形参传播深度。 */
int maxHolderDataFlowDepth() { result = 3 }
int maxIrqDataFlowDepth() { result = 3 }

/** 单条传播路径允许的局部变量初始化/赋值别名跳数。 */
int maxHolderLocalAliasHops() { result = 3 }
int maxIrqLocalAliasHops() { result = 3 }

/** 必须不小于上面的 holder 调用深度上限。 */
int maxBoundedCallDepth() { result = 4 }

predicate inTargetFileV1(File f) {
  f = f
}

predicate inTargetFunctionV1(Function f) {
  inTargetFileV1(f.getFile())
}

/** holder/registration/free 调用链范围由当前数据库决定。 */
predicate allowedCallBridgeFunctionV1(Function f) {
  inTargetFunctionV1(f)
}

/** IRQ handler/thread_fn 的传播范围由当前数据库决定。 */
predicate allowedIrqPropagationFunctionV1(Function f) {
  inTargetFunctionV1(f)
}


