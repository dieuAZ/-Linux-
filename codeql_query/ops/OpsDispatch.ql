/** @name Ops callback dispatch sites @kind table @id cpp/linux/ops-dispatch */
import cpp
import ops.OpsModel

string receiverExpression(FieldAccess methodAccess) {
  exists(FieldAccess opsAccess |
    methodAccess.getQualifier() = opsAccess and
    result = opsAccess.getQualifier().toString()
  )
  or
  result = methodAccess.getQualifier().toString()
}

from ExprCall call, FieldAccess fieldAccess, Struct interfaceType, Field methodField, Function dispatcher
where
  OpsModel::callbackDispatch(call, fieldAccess, interfaceType, methodField, dispatcher)
select
  interfaceType.getName() as interface_type,
  methodField.getName() as method_name,
  fieldAccess.getTarget().getName() as called_expression,
  receiverExpression(fieldAccess) as receiver_expression,
  fieldAccess.getQualifier().toString() as ops_expression,
  call.getFile().getRelativePath() as dispatch_file,
  call.getLocation().getStartLine() as dispatch_line,
  call.getLocation().getStartColumn() as dispatch_column,
  dispatcher.getQualifiedName() as dispatcher_name,
  dispatcher.getFile().getRelativePath() as dispatcher_file,
  dispatcher.getLocation().getStartLine() as dispatcher_definition_line