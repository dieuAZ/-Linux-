/**
 * @name Ops lifetime candidates by evidence level
 * @description Reports table/type discovery separately from member coverage and runtime evidence.
 * @kind table
 * @id cpp/linux/ops-candidate-levels
 */
import cpp
import ops.OpsCandidateEvidence

from Variable table, Struct iface, Field freeMethod, Function freeFn, int fi,
  FunctionCall release, Expr freed, string fp, Field useMethod, Function useFn,
  int ui, FieldAccess use, string up, int level, string relation
where
  OpsCandidateEvidence::pair(table, iface, freeMethod, freeFn, fi, release, freed,
    fp, useMethod, useFn, ui, use, up) and
  level = max(int l |
    OpsCandidateEvidence::evidence(table, iface, freeMethod, fi, useMethod, ui, fp, up, l) | l) and
  (freeFn = useFn and relation = "same_callback_order_requires_review"
   or freeFn != useFn and relation = "distinct_callbacks_overlap_unknown")
select table.getFile().getRelativePath() as table_file, table.getName() as ops_table,
  iface.getName() as interface_type, level as evidence_level,
  OpsCandidateEvidence::levelName(level) as evidence_kind,
  freeMethod.getName() as free_method, freeFn.getName() as free_function,
  fi as free_parameter, release.getLocation().getStartLine() as free_line,
  release.getTarget().getName() as free_api, fp as freed_path,
  useMethod.getName() as use_method, useFn.getName() as use_function,
  ui as use_parameter, use.getFile().getRelativePath() as use_file,
  use.getLocation().getStartLine() as use_line, up as used_path,
  relation as callback_relation,
  "unverified_not_a_confirmed_race" as concurrency_status
