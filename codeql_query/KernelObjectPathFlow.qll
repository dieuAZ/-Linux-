/** Shared bounded object-flow helpers for deferred callback models. */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow

predicate kernelLocalValueFlow(Expr sourceExpr, Expr sinkExpr) {
  exists(DataFlow::Node source, DataFlow::Node sink |
    source.asExpr() = sourceExpr and
    sink.asExpr() = sinkExpr and
    DataFlow::localFlow(source, sink)
  )
}

predicate kernelArgumentToParameterFlow(
  Expr callerExpr, FunctionCall call, int argumentIndex, Parameter calleeParameter
) {
  kernelLocalValueFlow(callerExpr, call.getArgument(argumentIndex)) and
  calleeParameter = call.getTarget().getParameter(argumentIndex)
}

predicate kernelFieldPathRoot(Expr expression, Variable root, int depth) {
  depth = 0 and exists(VariableAccess access |
    access = expression.getUnconverted() and root = access.getTarget()
  )
  or depth = 1 and exists(FieldAccess field, VariableAccess access |
    field = expression.getUnconverted() and
    access = field.getQualifier().getUnconverted() and root = access.getTarget()
  )
  or depth = 2 and exists(FieldAccess outer, FieldAccess inner, VariableAccess access |
    inner = expression.getUnconverted() and
    outer = inner.getQualifier().getUnconverted() and
    access = outer.getQualifier().getUnconverted() and root = access.getTarget()
  )
  or depth = 3 and exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, VariableAccess access |
    f3 = expression.getUnconverted() and f2 = f3.getQualifier().getUnconverted() and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget()
  )
  or depth = 4 and exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, FieldAccess f4, VariableAccess access |
    f4 = expression.getUnconverted() and f3 = f4.getQualifier().getUnconverted() and
    f2 = f3.getQualifier().getUnconverted() and f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget()
  )
  or depth = 5 and exists(FieldAccess f1, FieldAccess f2, FieldAccess f3, FieldAccess f4, FieldAccess f5, VariableAccess access |
    f5 = expression.getUnconverted() and f4 = f5.getQualifier().getUnconverted() and
    f3 = f4.getQualifier().getUnconverted() and f2 = f3.getQualifier().getUnconverted() and
    f1 = f2.getQualifier().getUnconverted() and
    access = f1.getQualifier().getUnconverted() and root = access.getTarget()
  )
}