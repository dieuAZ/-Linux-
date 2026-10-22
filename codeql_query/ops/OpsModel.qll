import cpp

module OpsModel {
  predicate opsStruct(Struct s) {
    exists(Field f, FunctionPointerType fp |
      f.getDeclaringType() = s and
      fp = f.getType().getUnspecifiedType()
    )
  }

  predicate callbackField(Struct s, Field f) {
    opsStruct(s) and
    f.getDeclaringType() = s and
    f.getType().getUnspecifiedType() instanceof FunctionPointerType
  }

  predicate boundFunction(Expr value, Function implementation) {
    exists(FunctionAccess access |
      value.getUnconverted() = access and access.getTarget() = implementation
    )
    or
    exists(AddressOfExpr address, FunctionAccess access |
      value.getUnconverted() = address and
      address.getOperand().getUnconverted() = access and
      access.getTarget() = implementation
    )
  }

  predicate aggregateBinding(Variable instance, Struct interfaceType, Field methodField, Function implementation) {
    instance.getType().getUnspecifiedType() = interfaceType and
    callbackField(interfaceType, methodField) and
    exists(ClassAggregateLiteral aggregate |
      instance.getInitializer().getExpr().getUnconverted() = aggregate and
      aggregate.getType().getUnspecifiedType() = interfaceType and
      exists(Expr value |
        aggregate.getAFieldExpr(methodField) = value and
        boundFunction(value, implementation)
      )
    ) and
    implementation.hasDefinition()
  }

  predicate callbackDispatch(ExprCall call, FieldAccess fieldAccess, Struct interfaceType, Field methodField, Function dispatcher) {
    (
      call.getExpr().getUnconverted() = fieldAccess
      or
      (
        not call.getExpr().getUnconverted() = fieldAccess and
        exists(PointerDereferenceExpr dereference |
          call.getExpr().getUnconverted() = dereference and
          dereference.getOperand().getUnconverted() = fieldAccess
        )
      )
    ) and
    methodField = fieldAccess.getTarget() and
    callbackField(interfaceType, methodField) and
    dispatcher = call.getEnclosingFunction()
  }
}