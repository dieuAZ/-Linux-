import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import ops.OpsValueSummaries
import concurrency.KernelLifetime

module OpsCallbackObjects {
  /** Track values derived from one concrete callback parameter. */
  predicate valueAt(Function entry, int index, Expr target, string path, int depth) {
    depth = 0 and path = "" and
    OpsValueSummaries::localValue(DataFlow::parameterNode(entry.getParameter(index)), DataFlow::exprNode(target))
    or
    exists(Expr parent, AddressOfExpr address, string prefix, int previous |
      previous >= 0 and previous < 5 and depth = previous + 1 and
      valueAt(entry, index, parent, prefix, previous) and
      address.getOperand().getUnconverted() = parent.getUnconverted() and
      OpsValueSummaries::localValue(DataFlow::exprNode(address), DataFlow::exprNode(target)) and
      path = prefix
    )
    or
    exists(Expr parent, FieldAccess field, string prefix, int previous |
      previous >= 0 and previous < 5 and depth = previous + 1 and
      valueAt(entry, index, parent, prefix, previous) and
      field.getQualifier() = parent and
      OpsValueSummaries::localValue(DataFlow::exprNode(field), DataFlow::exprNode(target)) and
      path = prefix + "." + field.getTarget().getName()
    )
    or
    exists(Expr host, FunctionCall getter, string prefix, string api, int previous |
      previous >= 0 and previous < 5 and depth = previous + 1 and
      OpsValueSummaries::privateGetter(getter, host, api) and
      valueAt(entry, index, host, prefix, previous) and
      OpsValueSummaries::localValue(DataFlow::exprNode(getter), DataFlow::exprNode(target)) and
      path = prefix + ".private:" + api
    )
    or
    exists(FunctionCall helper, int parameterIndex, Parameter parameter, VariableAccess access,
      string prefix, int previous |
      previous >= 0 and previous < 5 and depth = previous + 1 and
      not exists(Expr object | kernelReleaseObject(helper, object)) and
      not helper.getTarget().getName() in [
        "dev_get_drvdata", "platform_get_drvdata", "pci_get_drvdata", "usb_get_intfdata",
        "i2c_get_clientdata", "spi_get_drvdata", "netdev_priv"] and
      valueAt(entry, index, helper.getArgument(parameterIndex), prefix, previous) and
      parameter = helper.getTarget().getParameter(parameterIndex) and
      access.getTarget() = parameter and
      OpsValueSummaries::localValue(DataFlow::exprNode(access), DataFlow::exprNode(target)) and path = prefix
    )
    or
    exists(MacroInvocation recovery, Expr input, Expr root, Field first, Field last,
      string memberPath, string prefix, int previous |
      previous >= 0 and previous < 5 and depth = previous + 1 and
      kernelContainerRecovery(recovery, input, root, first, last, memberPath) and
      valueAt(entry, index, input, prefix, previous) and
      OpsValueSummaries::localValue(DataFlow::exprNode(root), DataFlow::exprNode(target)) and
      path = prefix + ".container:" + first.getDeclaringType().getName() + "::" + memberPath
    )
  }

  predicate callbackFree(Function entry, int index, FunctionCall release,
    Expr freed, string path, int depth) {
    kernelReleaseObject(release, freed) and valueAt(entry, index, freed, path, depth)
  }

  predicate callbackUse(Function entry, int index, FieldAccess use, string path, int depth) {
    exists(Expr object, string prefix |
      object = use.getQualifier() and valueAt(entry, index, object, prefix, depth) and
      path = prefix + "." + use.getTarget().getName()
    ) and
    not exists(FunctionCall release, Expr freed, string freePath, int freeDepth, int freeIndex |
      callbackFree(entry, freeIndex, release, freed, freePath, freeDepth) and freed.getUnconverted() = use
    )
    and not exists(FunctionCall release, Expr freed, AddressOfExpr head |
      kernelReleaseObject(release, freed) and
      release.getTarget().getName() in ["kvfree_call_rcu", "kfree_call_rcu_nolock"] and
      head = release.getArgument(0).getUnconverted() and
      head.getOperand().getUnconverted() = use
    )
  }
}
