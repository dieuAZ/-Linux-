/**
 * @name Ops function ranges
 * @description Exports the file and full source range of every defined function so
 *              the Python evidence layer can extract complete function bodies keyed
 *              by file and start position (not by name, which is ambiguous across
 *              translation units). The range spans the signature through the closing
 *              brace of the body.
 * @kind table
 * @id cpp/linux/ops-function-ranges
 */
import cpp

from Function f
where
  exists(f.getDefinition()) and
  exists(f.getDefinition().getBlock())
select
  f.getDefinition().getFile().getRelativePath() as file,
  f.getQualifiedName() as qualified_name,
  f.getName() as name,
  f.getDefinition().getLocation().getStartLine() as start_line,
  f.getDefinition().getBlock().getLocation().getEndLine() as end_line,
  f.getDefinition().getLocation().getStartColumn() as start_column,
  f.getDefinition().getBlock().getLocation().getEndColumn() as end_column
