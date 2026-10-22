import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import ops.OpsModel
import ops.OpsObjectTransfers

module OpsObjectFlow {
  predicate origin(DataFlow::Node node, string key, string kind) {
    exists(Parameter parameter |
      node = DataFlow::parameterNode(parameter) and
      parameter.getType().getUnspecifiedType() instanceof PointerType and
      key = parameter.getFunction().getQualifiedName() + ":parameter:" +
        parameter.getIndex().toString() and kind = "shared_parameter_value"
    )
    or
    exists(Expr expression |
      node = DataFlow::exprNode(expression) and
      expression.getType().getUnspecifiedType() instanceof PointerType and
      (expression instanceof FunctionCall or expression instanceof AddressOfExpr) and
      key = expression.getFile().getRelativePath() + ":" +
        expression.getLocation().getStartLine().toString() + ":" +
        expression.getLocation().getStartColumn().toString() and
      kind = "shared_expression_value"
    )
  }

  /** Direct-call argument propagation retains the caller's common origin. */
  predicate reachesArgument(
    DataFlow::Node source, ExprCall dispatch, int index, int depth, string trace
  ) {
    depth = 0 and
    exists(int steps, string evidence |
      OpsObjectTransfers::flow(source, DataFlow::exprNode(dispatch.getArgument(index)),
        steps, evidence) and
      trace = dispatch.getFile().getRelativePath() + ":" +
        dispatch.getLocation().getStartLine().toString() + " [" + evidence + "]"
    )
    or
    exists(FunctionCall call, int parameterIndex, int previousDepth, string tail |
      previousDepth >= 0 and previousDepth < 5 and depth = previousDepth + 1 and
      OpsObjectTransfers::valueFlow(source, DataFlow::exprNode(call.getArgument(parameterIndex))) and
      reachesArgument(DataFlow::parameterNode(call.getTarget().getParameter(parameterIndex)),
        dispatch, index, previousDepth, tail) and
      trace = call.getEnclosingFunction().getQualifiedName() + ":" +
        call.getLocation().getStartLine().toString() + " -> " + tail
    )
  }

  /** Associate an ops field store with its receiving pointer value. */
  predicate reachesBinding(DataFlow::Node source, Variable instance, int depth) {
    depth = 0 and
    exists(AssignExpr assignment, FieldAccess destination, AddressOfExpr address,
      VariableAccess table |
      assignment.getLValue().getUnconverted() = destination and
      assignment.getRValue().getUnconverted() = address and
      address.getOperand().getUnconverted() = table and table.getTarget() = instance and
      OpsObjectTransfers::valueFlow(source, DataFlow::exprNode(destination.getQualifier()))
    )
    or
    exists(FunctionCall call, int index, int previousDepth |
      previousDepth >= 0 and previousDepth < 5 and depth = previousDepth + 1 and
      OpsObjectTransfers::valueFlow(source, DataFlow::exprNode(call.getArgument(index))) and
      reachesBinding(DataFlow::parameterNode(call.getTarget().getParameter(index)),
        instance, previousDepth)
    )
  }

  predicate dispatch(ExprCall call, Struct interfaceType, Field method) {
    exists(FieldAccess access, Function function |
      OpsModel::callbackDispatch(call, access, interfaceType, method, function)
    )
  }

  predicate reachesReceiver(DataFlow::Node source, ExprCall call, int depth) {
    depth = 0 and
    exists(FieldAccess methodAccess, FieldAccess opsAccess, Struct interfaceType,
      Field method, Function dispatcher |
      OpsModel::callbackDispatch(call, methodAccess, interfaceType, method, dispatcher) and
      methodAccess.getQualifier().getUnconverted() = opsAccess and
      OpsObjectTransfers::valueFlow(source, DataFlow::exprNode(opsAccess.getQualifier()))
    )
    or
    exists(FunctionCall wrapper, int index, int previousDepth |
      previousDepth >= 0 and previousDepth < 5 and depth = previousDepth + 1 and
      OpsObjectTransfers::valueFlow(source, DataFlow::exprNode(wrapper.getArgument(index))) and
      reachesReceiver(DataFlow::parameterNode(wrapper.getTarget().getParameter(index)),
        call, previousDepth)
    )
  }
}
