/**
 * @name Ops lifetime candidates with compatible object member paths
 * @description Default recall view requires one concrete table, compatible parameter types and member coverage; dispatch evidence is optional.
 * @kind table
 * @id cpp/linux/ops-lifetime-candidates
 */
import cpp
import ops.OpsCandidateEvidence

from Variable table, Struct iface, Field freeMethod, Function freeFn, int fi,
  FunctionCall release, Expr freed, string fp, Field useMethod, Function useFn,
  int ui, FieldAccess use, string up, int level
where
  OpsCandidateEvidence::pair(table, iface, freeMethod, freeFn, fi, release, freed,
    fp, useMethod, useFn, ui, use, up) and
  freeFn != useFn and
  OpsCandidateEvidence::coveredPath(fp, up) and
  level = max(int l |
    OpsCandidateEvidence::evidence(table, iface, freeMethod, fi, useMethod, ui, fp, up, l) | l)
select table.getFile().getRelativePath() as table_file, table.getName() as ops_table,
  iface.getName() as interface_type, level as evidence_level,
  OpsCandidateEvidence::levelName(level) as evidence_kind,
  freeMethod.getName() as free_method, freeFn.getName() as free_function,
  release.getFile().getRelativePath() as free_file,
  release.getLocation().getStartLine() as free_line,
  release.getTarget().getName() as free_api, fp as freed_path,
  useMethod.getName() as use_method, useFn.getName() as use_function,
  use.getFile().getRelativePath() as use_file,
  use.getLocation().getStartLine() as use_line, up as used_path,
  "same_runtime_instance_unverified_unless_dispatch_evidence_present" as object_relation,
  "verify_dispatch_binding_order_and_framework_serialization" as review_boundary
