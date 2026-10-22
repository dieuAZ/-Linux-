import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import ops.OpsModel
import ops.OpsCallbackObjects
import ops.OpsObjectFlow

module OpsCandidateEvidence {
  /** Type agreement is a discovery filter, never runtime identity evidence. */
  predicate pair(Variable table, Struct iface, Field freeMethod, Function freeFn,
    int freeIndex, FunctionCall release, Expr freed, string freePath,
    Field useMethod, Function useFn, int useIndex, FieldAccess use, string usePath) {
    OpsModel::aggregateBinding(table, iface, freeMethod, freeFn) and
    OpsModel::aggregateBinding(table, iface, useMethod, useFn) and
    exists(PointerType ft, PointerType ut, int fd, int ud |
      ft = freeFn.getParameter(freeIndex).getType().getUnspecifiedType() and
      ut = useFn.getParameter(useIndex).getType().getUnspecifiedType() and
      ft.getBaseType().getUnspecifiedType() = ut.getBaseType().getUnspecifiedType() and
      ft.getBaseType().getUnspecifiedType() instanceof Struct and
      OpsCallbackObjects::callbackFree(freeFn, freeIndex, release, freed, freePath, fd) and
      OpsCallbackObjects::callbackUse(useFn, useIndex, use, usePath, ud)
    )
  }

  bindingset[freePath, usePath]
  predicate coveredPath(string freePath, string usePath) {
    // A field read must occur in the released object or one of its descendants.
    usePath.matches(freePath + ".%")
  }

  predicate commonArgument(ExprCall freeCall, int freeIndex, ExprCall useCall,
    int useIndex, DataFlow::Node origin) {
    exists(string key, string kind, int fd, int ud, string ft, string ut |
      OpsObjectFlow::origin(origin, key, kind) and
      OpsObjectFlow::reachesArgument(origin, freeCall, freeIndex, fd, ft) and
      OpsObjectFlow::reachesArgument(origin, useCall, useIndex, ud, ut)
    )
    or
    exists(Parameter root, string path, int fd, int ud |
      origin = DataFlow::parameterNode(root) and path != "" and
      OpsCallbackObjects::valueAt(root.getFunction(), root.getIndex(),
        freeCall.getArgument(freeIndex), path, fd) and
      OpsCallbackObjects::valueAt(root.getFunction(), root.getIndex(),
        useCall.getArgument(useIndex), path, ud)
    )
  }

  predicate dispatchPair(Struct iface, Field freeMethod, int freeIndex,
    Field useMethod, int useIndex, ExprCall freeCall, ExprCall useCall) {
    OpsObjectFlow::dispatch(freeCall, iface, freeMethod) and
    OpsObjectFlow::dispatch(useCall, iface, useMethod) and
    exists(DataFlow::Node origin |
      commonArgument(freeCall, freeIndex, useCall, useIndex, origin))
  }

  predicate receiverBound(Variable table, ExprCall freeCall, ExprCall useCall) {
    exists(DataFlow::Node receiver, string key, string kind, int bd, int fd, int ud |
      OpsObjectFlow::origin(receiver, key, kind) and
      OpsObjectFlow::reachesBinding(receiver, table, bd) and
      OpsObjectFlow::reachesReceiver(receiver, freeCall, fd) and
      OpsObjectFlow::reachesReceiver(receiver, useCall, ud))
  }

  bindingset[freeIndex, useIndex, freePath, usePath]
  predicate evidence(Variable table, Struct iface, Field freeMethod, int freeIndex,
    Field useMethod, int useIndex, string freePath, string usePath, int level) {
    level = 1
    or level = 2 and coveredPath(freePath, usePath)
    or level = 3 and coveredPath(freePath, usePath) and
      exists(ExprCall fc, ExprCall uc |
        dispatchPair(iface, freeMethod, freeIndex, useMethod, useIndex, fc, uc))
    or level = 4 and coveredPath(freePath, usePath) and
      exists(ExprCall fc, ExprCall uc |
        dispatchPair(iface, freeMethod, freeIndex, useMethod, useIndex, fc, uc) and
        receiverBound(table, fc, uc))
  }

  string levelName(int level) {
    level = 1 and result = "table_and_type_only"
    or level = 2 and result = "parameter_relative_lifetime_candidate"
    or level = 3 and result = "shared_dispatch_argument_candidate"
    or level = 4 and result = "bound_receiver_and_shared_argument_candidate"
  }
}
