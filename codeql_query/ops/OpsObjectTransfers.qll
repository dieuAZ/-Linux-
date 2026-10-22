import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import ops.OpsModel
import ops.OpsValueSummaries

module OpsObjectTransfers {
  /** Only reads in an ops dispatcher or a bounded wrapper chain are modeled. */
  predicate dispatchReachable(Function function, int depth) {
    depth = 0 and
    exists(ExprCall call, FieldAccess access, Struct interfaceType, Field method |
      OpsModel::callbackDispatch(call, access, interfaceType, method, function)
    )
    or
    exists(FunctionCall call, int previous |
      previous >= 0 and previous < 5 and depth = previous + 1 and
      call.getEnclosingFunction() = function and
      dispatchReachable(call.getTarget(), previous)
    )
  }

  /** Ordinary direct-call argument transport, without heap edges. */
  predicate plainReach(DataFlow::Node source, Expr target, int depth) {
    depth = 0 and OpsValueSummaries::localValue(source, DataFlow::exprNode(target))
    or
    exists(FunctionCall call, int index, int previous |
      previous >= 0 and previous < 3 and depth = previous + 1 and
      OpsValueSummaries::localValue(source, DataFlow::exprNode(call.getArgument(index))) and
      plainReach(DataFlow::parameterNode(call.getTarget().getParameter(index)), target, previous)
    )
  }

  /** Two access expressions must have a common host value witness. */
  predicate directSameHost(Expr left, Expr right) {
    exists(DataFlow::Node host, int leftDepth, int rightDepth |
      (
        exists(Parameter parameter | host = DataFlow::parameterNode(parameter))
        or
        exists(Expr seed |
          (seed instanceof AddressOfExpr or seed instanceof FunctionCall) and
          host = DataFlow::exprNode(seed)
        )
      ) and
      plainReach(host, left, leftDepth) and plainReach(host, right, rightDepth)
    )
  }

  predicate hostPath(Expr left, Expr right, int depth) {
    depth = 0 and directSameHost(left, right)
    or
    exists(FieldAccess leftField, FieldAccess rightField, int previous |
      previous >= 0 and previous < 2 and depth = previous + 1 and
      left.getUnconverted() = leftField and right.getUnconverted() = rightField and
      leftField.getTarget() = rightField.getTarget() and
      hostPath(leftField.getQualifier(), rightField.getQualifier(), previous)
    )
  }

  predicate sameHost(Expr left, Expr right) {
    exists(int depth | hostPath(left, right, depth))
  }

  predicate privateSetter(FunctionCall call, Expr host, Expr value, string slot) {
    call.getTarget().getName() in ["dev_set_drvdata", "platform_set_drvdata",
      "pci_set_drvdata", "usb_set_intfdata", "i2c_set_clientdata", "spi_set_drvdata"] and
    host = call.getArgument(0) and value = call.getArgument(1) and
    slot = call.getTarget().getName()
  }

  predicate privateGetter(FunctionCall call, Expr host, string slot) {
    exists(string api |
      OpsValueSummaries::privateGetter(call, host, api) and
      slot + "|" + api in [
        "dev_set_drvdata|dev_get_drvdata", "platform_set_drvdata|platform_get_drvdata",
        "pci_set_drvdata|pci_get_drvdata", "usb_set_intfdata|usb_get_intfdata",
        "i2c_set_clientdata|i2c_get_clientdata", "spi_set_drvdata|spi_get_drvdata"]
    )
  }

  predicate rawTransfer(Expr input, Expr output, string evidence) {
    exists(AssignExpr store, FieldAccess destination, FieldAccess read |
      destination = store.getLValue().getUnconverted() and
      destination.getTarget().getType().getUnspecifiedType() instanceof PointerType and
      read.getTarget() = destination.getTarget() and
      sameHost(destination.getQualifier(), read.getQualifier()) and
      input = store.getRValue() and output = read and
      evidence = "field:" + destination.getTarget().getDeclaringType().getName() +
        "." + destination.getTarget().getName()
    )
    or
    exists(FunctionCall setter, FunctionCall getter, Expr storeHost, Expr readHost,
      string slot |
      privateSetter(setter, storeHost, input, slot) and
      privateGetter(getter, readHost, slot) and sameHost(storeHost, readHost) and
      output = getter and evidence = "private_data:" + slot
    )
    or
    exists(MacroInvocation recovery, AddressOfExpr memberAddress, FieldAccess member,
      VariableAccess expandedInput, int depth |
      recovery.getMacroName() in ["container_of", "container_of_const"] and
      memberAddress.getOperand().getUnconverted() = member and
      member.getTarget().getType().getUnspecifiedType() instanceof Class and
      recovery.getUnexpandedArgument(2) = member.getTarget().getName() and
      (
        recovery.getUnexpandedArgument(1) = member.getTarget().getDeclaringType().getName()
        or recovery.getUnexpandedArgument(1) = "struct " +
          member.getTarget().getDeclaringType().getName()
      ) and
      expandedInput = recovery.getAnExpandedElement() and
      plainReach(DataFlow::exprNode(memberAddress), expandedInput, depth) and
      input = member.getQualifier() and output = recovery.getExpr() and
      evidence = "container_of:" + member.getTarget().getDeclaringType().getName() +
        "." + member.getTarget().getName()
    )
  }

  predicate transfer(Expr input, Expr output, string evidence) {
    rawTransfer(input, output, evidence) and
    exists(int depth | dispatchReachable(output.getEnclosingFunction(), depth))
  }

  /** At most two heap/API/recovery transitions, each with local pointer flow. */
  predicate flow(DataFlow::Node source, DataFlow::Node target, int steps, string evidence) {
    steps = 0 and OpsValueSummaries::localValue(source, target) and evidence = "local_or_return_value_flow"
    or
    exists(Expr input, Expr output, int previous, string prefix, string step |
      previous >= 0 and previous < 2 and steps = previous + 1 and
      flow(source, DataFlow::exprNode(input), previous, prefix) and
      transfer(input, output, step) and
      OpsValueSummaries::localValue(DataFlow::exprNode(output), target) and
      evidence = prefix + " -> " + step
    )
  }

  predicate valueFlow(DataFlow::Node source, DataFlow::Node target) {
    exists(int steps, string evidence | flow(source, target, steps, evidence))
  }
}
