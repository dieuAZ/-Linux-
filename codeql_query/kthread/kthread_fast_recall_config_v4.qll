/**
 * kthread_fast_recall_config_v4.qll
 *
 * 扫描范围由当前 CodeQL 数据库决定；include/ 仅作为传播 helper。
 */

import cpp

/** holder 到 start owner / free owner 的普通直接调用深度。 */
int maxHolderToStartCallDepth() { result = 4 }
int maxHolderToFreeCallDepth() { result = 4 }

/**
 * holder 侧、线程侧的实参到形参传播深度。
 * 线程侧设为 10，以覆盖回归测试中的深 helper 链和 container_of 恢复；
 * 传播仍受当前分目录数据库边界约束，避免退回跨全内核递归。
 */
int maxHolderDataFlowDepth() { result = 3 }
int maxThreadDataFlowDepth() { result = 10 }

/** 单条传播路径上的局部变量初始化/赋值别名跳数。 */
int maxHolderLocalAliasHops() { result = 3 }
int maxThreadLocalAliasHops() { result = 3 }

/** 必须不小于两个 holder 调用深度上限。 */
int maxBoundedCallDepth() { result = 4 }

predicate inTargetFileV4(File f) {
  f = f
}

predicate inTargetFunctionV4(Function f) {
  inTargetFileV4(f.getFile())
}

/** holder/start/free 调用链范围由当前数据库决定。 */
predicate allowedCallBridgeFunctionV4(Function f) {
  inTargetFunctionV4(f)
}

/** 线程侧传播范围由当前数据库决定。 */
predicate allowedThreadPropagationFunctionV4(Function f) {
  inTargetFunctionV4(f)
}


