/**
 * irq_fast_candidate_v2.qll
 *
 * V2 并发筛查的分层关系。
 *
 * 先在 registration + entry + dataPath + freePath 这一小键上确认 IRQ 回调侧
 * 存在与 free 路径兼容的真实 use，再与具体生命周期候选做连接。这样同一
 * 注册点下的多个 holder/root/free 候选不会重复驱动 IRQ 侧递归和 AST use 扫描。
 *
 * 本模块刻意不导入 irq_protection_v1：IRQ 注销/屏蔽/同步仅是人工审计标记，
 * 不属于本次并发筛查的必要条件，留给 V1 的详情查询按需补充。
 */

import cpp
import irq_reachable_data_access_v1
import irq_real_access_v1

/**
 * 半连接左侧：同一注册、入口、dev_id 路径和 free 路径至少有一个相容的真实 IRQ use。
 * 这个关系不携带 sink/holder/root，便于 CodeQL 在连接生命周期候选前
 * 复用 IRQ 侧有限传播结果。
 */
bindingset[registration, entry, dataPath, freePath]
predicate irqRegistrationEntryFreePathHasRealUseV2(
  IrqRegistrationCallV1 registration,
  Function entry,
  string dataPath,
  string freePath
) {
  exists(Function irqFunc, Expr access, string accessPath, string useKind |
    irqSideRealAccessV1(
      registration, entry, dataPath, irqFunc, access, accessPath, useKind
    ) and
    realUseHitsFreedPathV1(freePath, accessPath, useKind)
  )
}

/** 每个 free + registration + entry + holder/root/path 候选一行。 */
cached
predicate irqConcurrentFreeUseCandidateV2(
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
  irqRegistrationEntryFreePathHasRealUseV2(
    registration, entry, dataPath, freePath
  )
}

/** 每个与 free 路径兼容的真实 IRQ use-site 一行。 */
cached
predicate irqConcurrentFreeUseAccessV2(
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
  irqConcurrentFreeUseCandidateV2(
    sink, holder, registration, holderRoot, entry, handlerKind,
    dataPath, freePath, holderToRegistrationDepth, holderToFreeDepth
  ) and
  irqSideRealAccessV1(
    registration, entry, dataPath, irqFunc, access, accessPath, useKind
  ) and
  realUseHitsFreedPathV1(freePath, accessPath, useKind)
}


