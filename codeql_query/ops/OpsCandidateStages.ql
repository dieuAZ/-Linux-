/**
 * @name Ops candidate stage counts
 * @kind table
 * @id cpp/linux/ops-candidate-stage-counts
 */
import cpp
import ops.OpsModel
import ops.OpsCallbackObjects
import ops.OpsCandidateEvidence

predicate stage(string name, int n) {
  name = "01_bindings" and n = count(Variable v, Struct t, Field f, Function fn |
    OpsModel::aggregateBinding(v, t, f, fn))
  or name = "02_free_callbacks" and n = count(Variable v, Struct t, Field f, Function fn |
    OpsModel::aggregateBinding(v, t, f, fn) and
    exists(int i, FunctionCall fc, Expr o, string p, int d |
      OpsCallbackObjects::callbackFree(fn, i, fc, o, p, d)))
  or name = "03_use_callbacks" and n = count(Variable v, Struct t, Field f, Function fn |
    OpsModel::aggregateBinding(v, t, f, fn) and
    exists(int i, FieldAccess u, string p, int d |
      OpsCallbackObjects::callbackUse(fn, i, u, p, d)))
  or name = "04_level_1" and n = count(Variable v, Struct t, Field ff, Function fn, int fi,
      FunctionCall fc, Expr o, string fp, Field uf, Function un, int ui, FieldAccess u, string up |
      OpsCandidateEvidence::pair(v, t, ff, fn, fi, fc, o, fp, uf, un, ui, u, up) and
      OpsCandidateEvidence::evidence(v, t, ff, fi, uf, ui, fp, up, 1))
  or name = "05_level_2" and n = count(Variable v, Struct t, Field ff, Function fn, int fi,
      FunctionCall fc, Expr o, string fp, Field uf, Function un, int ui, FieldAccess u, string up |
      OpsCandidateEvidence::pair(v, t, ff, fn, fi, fc, o, fp, uf, un, ui, u, up) and
      OpsCandidateEvidence::evidence(v, t, ff, fi, uf, ui, fp, up, 2))
  or name = "06_level_3" and n = count(Variable v, Struct t, Field ff, Function fn, int fi,
      FunctionCall fc, Expr o, string fp, Field uf, Function un, int ui, FieldAccess u, string up |
      OpsCandidateEvidence::pair(v, t, ff, fn, fi, fc, o, fp, uf, un, ui, u, up) and
      OpsCandidateEvidence::evidence(v, t, ff, fi, uf, ui, fp, up, 3))
  or name = "07_level_4" and n = count(Variable v, Struct t, Field ff, Function fn, int fi,
      FunctionCall fc, Expr o, string fp, Field uf, Function un, int ui, FieldAccess u, string up |
      OpsCandidateEvidence::pair(v, t, ff, fn, fi, fc, o, fp, uf, un, ui, u, up) and
      OpsCandidateEvidence::evidence(v, t, ff, fi, uf, ui, fp, up, 4))
}
from string name, int n where stage(name, n) select name as stage, n as row_count
