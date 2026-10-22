import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import concurrency.KernelLifetime

/** Each mechanism supplies the actual event, owner, and callback root. */
signature module ConfigSig {
  predicate registration(Locatable event, Expr owner, Function callback,
    Expr callbackRoot, string recovery, string eventKind);
  predicate protection(FunctionCall release, string tag, string context);
}

class Release extends FunctionCall {
    Release() {
      exists(Expr object | kernelReleaseObject(this, object))
    }
    Expr getObject() {
      kernelReleaseObject(this, result)
    }
  }

module FreeDriven<ConfigSig Config> {
  predicate local(Expr source, Expr target) {
    DataFlow::localFlow(DataFlow::exprNode(source), DataFlow::exprNode(target))
  }

  /** Bounded concrete argument-to-parameter edges, including local aliases. */
  predicate reach(DataFlow::Node source, Expr target, int depth) {
    depth = 0 and DataFlow::localFlow(source, DataFlow::exprNode(target))
    or
    exists(FunctionCall call, int index, int previous |
      previous >= 0 and previous < 3 and depth = previous + 1 and
      DataFlow::localFlow(source, DataFlow::exprNode(call.getArgument(index))) and
      reach(DataFlow::parameterNode(call.getTarget().getParameter(index)), target, previous)
    )
  }

  predicate seed(DataFlow::Node source, string key) {
    exists(Parameter parameter |
      source = DataFlow::parameterNode(parameter) and
      key = parameter.getFile().getRelativePath() + ":" +
        parameter.getFunction().getLocation().getStartLine().toString() + ":parameter:" +
        parameter.getIndex().toString()
    )
    or
    exists(Expr expression |
      (expression instanceof AddressOfExpr or expression instanceof FunctionCall) and
      source = DataFlow::exprNode(expression) and
      key = expression.getFile().getRelativePath() + ":" +
        expression.getLocation().getStartLine().toString() + ":" +
        expression.getLocation().getStartColumn().toString()
    )
  }

  predicate sharedValue(Expr left, Expr right, string key) {
    exists(DataFlow::Node source, int leftDepth, int rightDepth |
      seed(source, key) and reach(source, left, leftDepth) and reach(source, right, rightDepth)
    )
  }

  predicate rootPath(Expr expression, Expr root, string path, int depth) {
    depth = 0 and root = expression.getUnconverted() and path = ""
    or
    exists(FieldAccess field, string prefix, int previous |
      expression.getUnconverted() = field and previous >= 0 and previous < 3 and
      depth = previous + 1 and rootPath(field.getQualifier(), root, prefix, previous) and
      path = prefix + "." + field.getTarget().getName()
    )
  }

  predicate hostIdentity(Expr left, Expr right, string key, int depth) {
    depth = 0 and sharedValue(left, right, key)
    or
    exists(FieldAccess a, FieldAccess b, int previous |
      left.getUnconverted() = a and right.getUnconverted() = b and
      a.getTarget() = b.getTarget() and previous >= 0 and previous < 2 and
      depth = previous + 1 and hostIdentity(a.getQualifier(), b.getQualifier(), key, previous)
    )
  }

  /** Storage slots are keyed by global entity or proven common host + actual Field. */
  predicate slotPair(Expr store, Expr read, string key) {
    exists(VariableAccess a, VariableAccess b, GlobalVariable global |
      store.getUnconverted() = a and read.getUnconverted() = b and
      a.getTarget() = global and b.getTarget() = global and
      key = "global:" + global.getFile().getRelativePath() + ":" +
        global.getLocation().getStartLine().toString() + ":" + global.getName()
    )
    or
    exists(FieldAccess a, FieldAccess b, string hostKey, int depth |
      store.getUnconverted() = a and read.getUnconverted() = b and
      a.getTarget() = b.getTarget() and hostIdentity(a.getQualifier(), b.getQualifier(), hostKey, depth) and
      key = hostKey + ":field:" + a.getTarget().getDeclaringType().getName() +
        "." + a.getTarget().getName()
    )
  }

  predicate privatePair(FunctionCall setter, FunctionCall getter) {
    setter.getTarget().getName() + "|" + getter.getTarget().getName() in [
      "dev_set_drvdata|dev_get_drvdata", "platform_set_drvdata|platform_get_drvdata",
      "pci_set_drvdata|pci_get_drvdata", "usb_set_intfdata|usb_get_intfdata",
      "i2c_set_clientdata|i2c_get_clientdata", "spi_set_drvdata|spi_get_drvdata"]
  }

  /** Link a published object to a later load, without claiming overwrite ordering. */
  predicate storageLink(Expr published, Expr loaded, string key, string kind) {
    exists(AssignExpr assignment, Expr read, int depth |
      assignment.getRValue() = published and slotPair(assignment.getLValue(), read, key) and
      reach(DataFlow::exprNode(read), loaded, depth) and kind = "shared_storage_slot"
    )
    or
    exists(FunctionCall setter, FunctionCall getter, int hostDepth, int loadDepth |
      privatePair(setter, getter) and published = setter.getArgument(1) and
      hostIdentity(setter.getArgument(0), getter.getArgument(0), key, hostDepth) and
      reach(DataFlow::exprNode(getter), loaded, loadDepth) and kind = "private_data_common_host"
    )
    or
    exists(MacroInvocation publication, Expr destination, Expr value, Expr read, int depth |
      publication.getMacroName() in ["rcu_assign_pointer", "RCU_INIT_POINTER"] and
      destination = publication.getAnExpandedElement() and
      value = publication.getAnExpandedElement() and
      destination.toString() = publication.getUnexpandedArgument(0) and
      value.toString() = publication.getUnexpandedArgument(1) and
      published = value and slotPair(destination, read, key) and
      reach(DataFlow::exprNode(read), loaded, depth) and kind = "rcu_publication_slot"
    )
  }

  predicate pointerRelation(Expr registered, Expr freedRoot, string key, string evidence) {
    sharedValue(registered, freedRoot, key) and evidence = "common_pointer_value"
    or
    exists(Expr published, string slotKind |
      storageLink(published, freedRoot, key, slotKind) and
      exists(string sourceKey | sharedValue(published, registered, sourceKey)) and
      evidence = slotKind
    )
    or
    exists(Expr published, string slotKind |
      storageLink(published, registered, key, slotKind) and
      exists(string sourceKey | sharedValue(published, freedRoot, sourceKey)) and
      evidence = slotKind
    )
    or
    exists(Expr publicationA, Expr publicationB, string kindA, string kindB, string sourceKey |
      storageLink(publicationA, registered, key, kindA) and
      storageLink(publicationB, freedRoot, key, kindB) and
      sharedValue(publicationA, publicationB, sourceKey) and evidence = "common_published_value"
    )
  }

  predicate objectRelation(Expr registered, Expr freedRoot, string key, string evidence) {
    pointerRelation(registered, freedRoot, key, evidence)
    or
    exists(FunctionCall factory, ReturnStmt returned, string sourceKey, string returnEvidence |
      factory.getTarget() = returned.getEnclosingFunction() and
      registered.getEnclosingFunction() = returned.getEnclosingFunction() and
      sharedValue(registered, returned.getExpr(), sourceKey) and
      pointerRelation(factory, freedRoot, key, returnEvidence) and
      evidence = "returned_registered_object:" + returnEvidence
    )
    or
    exists(FunctionCall getter, int depth, string hostEvidence |
      getter.getTarget().hasName("netdev_priv") and
      reach(DataFlow::exprNode(getter), registered, depth) and
      pointerRelation(getter.getArgument(0), freedRoot, key, hostEvidence) and
      evidence = "netdev_private_allocation:" + hostEvidence
    )
  }

  predicate executionPath(Function caller, Function callee, int depth) {
    depth = 0 and caller = callee
    or
    exists(FunctionCall call, int previous |
      call.getEnclosingFunction() = caller and previous >= 0 and previous < 4 and
      depth = previous + 1 and executionPath(call.getTarget(), callee, previous)
    )
  }

  /** Direct branch exists only when the event can reach this free through callers. */
  predicate directBranch(Locatable event, Release release) {
    exists(FunctionCall start, int depth |
      start = event and
      (
        depth = 0 and start.getEnclosingFunction() = release.getEnclosingFunction() and
        start.getASuccessor+() = release
        or
        exists(FunctionCall next |
          start.getEnclosingFunction() = next.getEnclosingFunction() and
          start.getASuccessor+() = next and
          executionPath(next.getTarget(), release.getEnclosingFunction(), depth)
        )
      )
    )
  }

  /** Validate recovery against the incoming member pointer, not type/name alone. */
  predicate recoveredRoot(Function callback, Field member, Expr root) {
    exists(MacroInvocation recovery, Expr input, Field first, string path, int index |
      recovery.getEnclosingFunction() = callback and
      kernelContainerRecovery(recovery, input, root, first, member, path) and first = member and
      DataFlow::localFlow(DataFlow::parameterNode(callback.getParameter(index)),
        DataFlow::exprNode(input))
    )
  }

  predicate callbackUse(Expr callbackRoot, FieldAccess use, string path, int depth) {
    exists(Expr localRoot, string suffix, int fieldDepth |
      reach(DataFlow::exprNode(callbackRoot), localRoot, depth) and
      rootPath(use, localRoot, suffix, fieldDepth) and fieldDepth > 0 and path = suffix
    )
    or
    exists(FunctionCall getter, Expr host, Expr privateRoot, string suffix, int hostDepth,
      int privateDepth, int fieldDepth |
      getter.getTarget().hasName("netdev_priv") and host = getter.getArgument(0) and
      reach(DataFlow::exprNode(callbackRoot), host, hostDepth) and
      reach(DataFlow::exprNode(getter), privateRoot, privateDepth) and
      rootPath(use, privateRoot, suffix, fieldDepth) and fieldDepth > 0 and
      path = ".private:netdev_priv" + suffix and depth = hostDepth + privateDepth + 1 and depth <= 3
    )
    or
    exists(FieldAccess child, string prefix, int firstDepth, Expr alias,
      string suffix, int fieldDepth, int helperDepth |
      callbackUse(callbackRoot, child, prefix, firstDepth) and
      firstDepth >= 0 and firstDepth < 3 and
      reach(DataFlow::exprNode(child), alias, helperDepth) and helperDepth <= 2 and
      rootPath(use, alias, suffix, fieldDepth) and fieldDepth > 0 and
      path = prefix + suffix and path.length() <= 160 and
      depth = firstDepth + helperDepth + 1 and depth <= 3
    )
  }

  predicate candidate(Release release, Locatable event, Expr owner, Function callback,
    FieldAccess use, string freePath, string usePath, string branch,
    string key, string evidence, string recovery, string eventKind, int useDepth) {
    exists(Expr callbackRoot, Expr freeRoot, int freeDepth |
      Config::registration(event, owner, callback, callbackRoot, recovery, eventKind) and
      rootPath(release.getObject(), freeRoot, freePath, freeDepth) and
      objectRelation(owner, freeRoot, key, evidence) and
      callbackUse(callbackRoot, use, usePath, useDepth) and
      (freePath = "" or usePath = freePath or usePath.indexOf(freePath + ".") = 0) and
      not exists(Release callbackRelease | callbackRelease.getAnArgument() = use) and
      (
        directBranch(event, release) and branch = "free_chain_event"
        or
        not directBranch(event, release) and branch = "other_entry_object_relation"
      )
    )
  }
}
