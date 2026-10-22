import cpp

/** Release operands, rather than allocator/pool or RCU-head operands. */
predicate kernelReleaseObject(FunctionCall call, Expr object) {
  call.getTarget().getName() in ["free", "kfree", "kfree_sensitive", "kfree_const",
    "kvfree", "kvfree_sensitive", "vfree", "free_netdev", "mempool_free",
    "kfree_rcu", "kvfree_rcu"] and object = call.getArgument(0)
  or
  call.getTarget().getName() in ["kmem_cache_free", "devm_kfree"] and
  object = call.getArgument(1)
  or
  exists(PointerType pointer |
    call.getTarget().getName() in ["kvfree_call_rcu", "kfree_call_rcu_nolock"] and
    pointer = call.getTarget().getParameter(1).getType().getUnspecifiedType() and
    pointer.getBaseType().getUnspecifiedType() instanceof VoidType and
    object = call.getArgument(1)
  )
}

/** Resolve each path component against an actual Field in its declaring type. */
predicate kernelMemberPath(Type holder, string path, Field first, Field last, int depth) {
  depth = 0 and first = last and first.getDeclaringType().stripType() = holder.stripType() and
  path = first.getName()
  or
  exists(Field child, string suffix, int previous |
    previous >= 0 and previous < 3 and depth = previous + 1 and
    first.getDeclaringType().stripType() = holder.stripType() and
    kernelMemberPath(first.getType(), suffix, child, last, previous) and
    path = first.getName() + "." + suffix
  )
}

/** Derive typeof/const wrapper types from the extracted result, not its spelling. */
predicate kernelContainerRecovery(MacroInvocation recovery, Expr input, Expr root,
  Field first, Field last, string path) {
  exists(PointerType pointer, int depth, int inputIndex |
    recovery.getMacroName() in ["container_of", "container_of_const", "from_timer",
      "timer_container_of", "from_tasklet"] and
    root = recovery.getExpr() and
    pointer = root.getFullyConverted().getType().getUnspecifiedType() and
    path = recovery.getUnexpandedArgument(2) and
    kernelMemberPath(pointer.getBaseType(), path, first, last, depth) and
    (
      recovery.getMacroName() in ["container_of", "container_of_const"] and inputIndex = 0
      or recovery.getMacroName() in ["from_timer", "timer_container_of", "from_tasklet"] and
        inputIndex = 1
    ) and
    input = recovery.getAnExpandedElement() and
    input.toString() = recovery.getUnexpandedArgument(inputIndex)
  )
}
