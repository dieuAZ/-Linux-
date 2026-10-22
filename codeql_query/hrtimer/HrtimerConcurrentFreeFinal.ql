/**
 * @name Linux hrtimer concurrent free/use candidates - final
 * @description Reports bounded setup/start/free paths whose released owner
 *              subtree is really accessed by the registered hrtimer callback.
 * @kind table
 * @id cpp/linux/hrtimer-concurrent-free-use-final
 */

import HrtimerConcurrentFreeLight

from HrtimerConcurrentFreeRow row
select
  "hrtimer" as concurrency_model,
  "concurrent_free_real_use" as query_pattern,
  "real_use_detail" as match_kind,
  "same_declared_field_subtree" as match_basis,

  row.getLifecycleFile() as lifecycle_file,
  row.getLifecycleLine() as lifecycle_line,
  row.getLifecycleFunction() as lifecycle_function,
  row.getLifecycleApi() as lifecycle_api,
  "hrtimer_start" as lifecycle_kind,
  row.getLifecycleArgument() as lifecycle_argument,
  row.getLifecycleBinding() as lifecycle_binding,
  row.getStartWrapperDepth() as lifecycle_to_callback_depth,
  row.getFreeCallDepth() as lifecycle_to_free_depth,

  row.getSetupFile() as setup_file,
  row.getSetupLine() as setup_line,
  row.getSetupFunction() as setup_function,
  row.getSetupApi() as setup_api,
  row.getSetupBinding() as setup_binding,

  row.getCallbackName() as callback_entry,
  row.getCallbackName() as callback_function,
  row.getCallbackFile() as callback_file,
  row.getCallbackLine() as callback_line,
  row.getCallbackKind() as callback_kind,
  row.getCallbackRecovery() as callback_recovery,
  row.getCallbackCallDepth() as callback_call_depth,

  row.getHolderFunction() as holder_function,
  row.getHolderRoot() as holder_root,
  "hrtimer_owner_expression" as holder_root_kind,
  row.getHolderType() as holder_type,
  row.getHrtimerFieldName() as callback_data_path,

  row.getFreeFile() as free_file,
  row.getFreeLine() as free_line,
  row.getFreeFunction() as free_function,
  row.getFreeApi() as free_api,
  row.getFreeKind() as free_kind,
  row.getFreedExpression() as freed_expression,
  row.getFreedObjectPath() as freed_object_path,
  row.getFreedPathKind() as freed_path_kind,
  row.getFreeCallDepth() as free_call_depth,

  row.getUseFile() as use_file,
  row.getUseLine() as use_line,
  row.getUseFunction() as use_function,
  row.getUseExpression() as use_expression,
  "field_access" as use_kind,
  row.getUsedObjectPath() as used_object_path,
  "use_is_at_or_below_freed_subtree" as path_relation,

  row.getProtectionTag() as protection_tag,
  "yes=cancel/wait-running before free; unknown=try-to-cancel only; no=no modeled hrtimer barrier. Same-function lexical context is not an identity proof." as protection_detail,
  row.getBarrierContext() as barrier_context,
  "allocation_boundary_requires_review" as allocation_boundary_context,
  "Cross-lifecycle type/file matching is a candidate approximation; verify runtime identity, hrtimer_cancel ordering, and HRTIMER_RESTART behavior." as review_boundary,

  row.getLifecycleFile() as auxiliary_file,
  row.getLifecycleLine() as auxiliary_line,
  row.getLifecycleFunction() as auxiliary_function,
  row.getLifecycleArgument() as auxiliary_expression
