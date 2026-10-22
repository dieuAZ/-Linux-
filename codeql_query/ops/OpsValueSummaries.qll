import cpp
import semmle.code.cpp.dataflow.new.DataFlow

module OpsValueSummaries {
  predicate returnedParameter(Function function, int index, int depth) {
    exists(ReturnStmt returned |
      returned.getEnclosingFunction() = function and
      (
        depth = 0 and DataFlow::localFlow(DataFlow::parameterNode(function.getParameter(index)),
          DataFlow::exprNode(returned.getExpr()))
        or
        exists(FunctionCall inner, int argument, int previous |
          previous >= 0 and previous < 2 and depth = previous + 1 and
          inner.getEnclosingFunction() = function and
          DataFlow::localFlow(DataFlow::parameterNode(function.getParameter(index)),
            DataFlow::exprNode(inner.getArgument(argument))) and
          returnedParameter(inner.getTarget(), argument, previous) and
          DataFlow::localFlow(DataFlow::exprNode(inner), DataFlow::exprNode(returned.getExpr()))
        )
      )
    )
  }

  /** Call summaries pair each argument with the result of that same call. */
  predicate localValue(DataFlow::Node source, DataFlow::Node target, int depth) {
    depth = 0 and DataFlow::localFlow(source, target)
    or
    exists(FunctionCall call, int index, int summaryDepth, int previous |
      previous >= 0 and previous < 3 and depth = previous + 1 and
      localValue(source, DataFlow::exprNode(call.getArgument(index)), previous) and
      returnedParameter(call.getTarget(), index, summaryDepth) and
      DataFlow::localFlow(DataFlow::exprNode(call), target)
    )
  }

  predicate localValue(DataFlow::Node source, DataFlow::Node target) {
    exists(int depth | localValue(source, target, depth))
  }

  predicate getterSummary(Function function, int index, string api, int depth) {
    depth = 0 and index = 0 and api = function.getName() and api in [
      "dev_get_drvdata", "platform_get_drvdata", "pci_get_drvdata", "usb_get_intfdata",
      "i2c_get_clientdata", "spi_get_drvdata", "netdev_priv"]
    or
    exists(FunctionCall inner, ReturnStmt returned, int argument, int previous |
      previous >= 0 and previous < 2 and depth = previous + 1 and
      inner.getEnclosingFunction() = function and returned.getEnclosingFunction() = function and
      getterSummary(inner.getTarget(), argument, api, previous) and
      localValue(DataFlow::parameterNode(function.getParameter(index)),
        DataFlow::exprNode(inner.getArgument(argument))) and
      localValue(DataFlow::exprNode(inner), DataFlow::exprNode(returned.getExpr()))
    )
  }

  predicate privateGetter(FunctionCall call, Expr host, string api) {
    exists(int index, int depth |
      getterSummary(call.getTarget(), index, api, depth) and host = call.getArgument(index)
    )
  }
}
