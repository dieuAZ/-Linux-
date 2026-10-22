/**
 * @name Concrete ops method bindings
 * @description Lists every callback bound into every aggregate-initialized ops table.
 * @kind table
 * @id cpp/linux/ops-bindings
 */

import cpp
import ops.OpsModel

from
  Variable instance,
  Struct interfaceType,
  Field methodField,
  Function implementation
where
  OpsModel::aggregateBinding(instance, interfaceType, methodField, implementation)
select
  interfaceType.getName() + ":" +
    instance.getFile().getRelativePath() + ":" +
    instance.getLocation().getStartLine().toString() + ":" +
    instance.getName() as ops_instance_id,
  interfaceType.getName() as interface_type,
  instance.getName() as instance_name,
  instance.getFile().getRelativePath() as instance_file,
  instance.getLocation().getStartLine() as instance_line,
  methodField.getName() as method_name,
  implementation.getQualifiedName() as implementation_name,
  implementation.getDefinition().getFile().getRelativePath() as implementation_file,
  implementation.getDefinition().getLocation().getStartLine() as implementation_definition_line,
  methodField.getFile().getRelativePath() as method_definition_file,
  methodField.getLocation().getStartLine() as method_definition_line
