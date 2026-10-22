/**
 * V2 详情查询：每个与 freePath 兼容的真实 IRQ 回调 use-site 一行。
 *
 * 不直接判断漏洞；同函数 free 前的 IRQ 注销/屏蔽/同步作为审计 tag 输出。
 */

import cpp
import find_before
import irq_reachable_data_access_v1
import irq_fast_candidate_v2

class IrqProtectionCallFinal extends FunctionCall {
  IrqProtectionCallFinal() {
    this.getTarget().hasName("free_irq") or
    this.getTarget().hasName("devm_free_irq") or
    this.getTarget().hasName("disable_irq") or
    this.getTarget().hasName("synchronize_irq") or
    this.getTarget().hasName("disable_irq_nosync") or
    this.getTarget().hasName("disable_hardirq") or
    this.getTarget().hasName("synchronize_hardirq") or
    this.getTarget().hasName("disable_percpu_irq") or
    this.getTarget().hasName("free_percpu_irq") or
    this.getTarget().hasName("devm_free_percpu_irq") or
    this.getTarget().hasName("free_nmi")
  }

  string getApiName() { result = this.getTarget().getName() }
  string getStrength() {
    (
      this.getTarget().hasName("free_irq") or
      this.getTarget().hasName("devm_free_irq") or
      this.getTarget().hasName("disable_irq") or
      this.getTarget().hasName("synchronize_irq")
    ) and result = "strong"
    or
    (
      this.getTarget().hasName("disable_irq_nosync") or
      this.getTarget().hasName("disable_hardirq") or
      this.getTarget().hasName("synchronize_hardirq") or
      this.getTarget().hasName("disable_percpu_irq") or
      this.getTarget().hasName("free_percpu_irq") or
      this.getTarget().hasName("devm_free_percpu_irq") or
      this.getTarget().hasName("free_nmi")
    ) and result = "weak"
  }
}

predicate irqProtectionLexicallyBeforeFreeFinal(
  IrqProtectionCallFinal protection, FreeLikeSink sink
) {
  protection.getEnclosingFunction() = sink.getEnclosingFunction() and
  (
    protection.getLocation().getStartLine() < sink.getLocation().getStartLine()
    or
    protection.getLocation().getStartLine() = sink.getLocation().getStartLine() and
    protection.getLocation().getStartColumn() < sink.getLocation().getStartColumn()
  )
}

string irqProtectionContextFinal(FreeLikeSink sink) {
  exists(IrqProtectionCallFinal protection |
    irqProtectionLexicallyBeforeFreeFinal(protection, sink) and
    result = protection.getStrength() + "_barrier_before_free:" + protection.getApiName()
  )
  or
  not exists(IrqProtectionCallFinal protection |
    irqProtectionLexicallyBeforeFreeFinal(protection, sink)
  ) and result = "none_in_free_function_before_free"
}

string irqProtectionTagFinal(FreeLikeSink sink) {
  exists(IrqProtectionCallFinal protection |
    irqProtectionLexicallyBeforeFreeFinal(protection, sink) and
    protection.getStrength() = "strong"
  ) and result = "yes"
  or
  not exists(IrqProtectionCallFinal protection |
    irqProtectionLexicallyBeforeFreeFinal(protection, sink) and
    protection.getStrength() = "strong"
  ) and
  exists(IrqProtectionCallFinal protection |
    irqProtectionLexicallyBeforeFreeFinal(protection, sink) and
    protection.getStrength() = "weak"
  ) and result = "unknown"
  or
  not exists(IrqProtectionCallFinal protection |
    irqProtectionLexicallyBeforeFreeFinal(protection, sink)
  ) and result = "no"
}

from
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
where
  irqConcurrentFreeUseAccessV2(
    sink, holder, registration, holderRoot, entry, handlerKind,
    irqFunc, access, dataPath, freePath, accessPath, useKind,
    holderToRegistrationDepth, holderToFreeDepth
  )
select
  "irq" as concurrency_model,
  "concurrent_free_real_use" as query_pattern,
  "real_use_detail" as match_kind,
  "same_or_descendant_freed_path" as match_basis,

  registration.getFile().getRelativePath() as lifecycle_file,
  registration.getLocation().getStartLine() as lifecycle_line,
  registration.getEnclosingFunction().getName() as lifecycle_function,
  registration.getTarget().getName() as lifecycle_api,
  handlerKind as lifecycle_kind,
  registration.toString() as lifecycle_argument,
  "" as lifecycle_binding,
  holderToRegistrationDepth as lifecycle_to_callback_depth,
  holderToFreeDepth as lifecycle_to_free_depth,

  "" as setup_file,
  "" as setup_line,
  "" as setup_function,
  "" as setup_api,
  "" as setup_binding,

  entry.getName() as callback_entry,
  "" as callback_function,
  entry.getFile().getRelativePath() as callback_file,
  entry.getLocation().getStartLine() as callback_line,
  handlerKind as callback_kind,
  "irq_dev_id_parameter" as callback_recovery,
  "" as callback_call_depth,

  holder.getName() as holder_function,
  holderRoot.toString() as holder_root,
  "variable" as holder_root_kind,
  holderRoot.getType().toString() as holder_type,
  dataPath as callback_data_path,

  sink.getFile().getRelativePath() as free_file,
  sink.getLocation().getStartLine() as free_line,
  sink.getEnclosingFunction().getName() as free_function,
  sink.getTarget().getName() as free_api,
  sink.getFreeKind() as free_kind,
  sink.toString() as freed_expression,
  freePath as freed_object_path,
  "whole_or_subobject; see freed_object_path" as freed_path_kind,
  holderToFreeDepth as free_call_depth,

  access.getFile().getRelativePath() as use_file,
  access.getLocation().getStartLine() as use_line,
  irqFunc.getName() as use_function,
  access.toString() as use_expression,
  useKind as use_kind,
  accessPath as used_object_path,
  "same_or_descendant_freed_path" as path_relation,

  irqProtectionTagFinal(sink) as protection_tag,
  "yes=free_irq/devm_free_irq/disable_irq/synchronize_irq before free; unknown=nosync/hardirq/percpu/NMI protection only; no=no modeled IRQ protection. Verify IRQ/dev_id identity." as protection_detail,
  irqProtectionContextFinal(sink) as barrier_context,
  "allocation_boundary_requires_review" as allocation_boundary_context,
  "Candidate only: verify allocation boundaries, runtime IRQ identity, ordering, and IRQ quiescence." as review_boundary,

  "" as auxiliary_file,
  "" as auxiliary_line,
  "" as auxiliary_function,
  "" as auxiliary_expression

