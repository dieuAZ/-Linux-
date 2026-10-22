import cpp

/**
 * 和 container_of 同类的“宿主对象恢复”宏。
 *
 * 第一版纳入：
 * - container_of(ptr, type, member)
 * - container_of_const(ptr, type, member)
 * - list_entry(ptr, type, member)
 * - hlist_entry(ptr, type, member)
 * - rb_entry(ptr, type, member)
 * - from_timer(var, timer_ptr, member)
 *
 * 这里的共同语义都是：
 *   已知“某个成员对象/成员指针”对应的路径 P.member
 *   恢复出宿主对象路径 P
 */
class ContainerLikeMacro extends MacroInvocation {
  ContainerLikeMacro() {
    (
      this.getMacroName() = "container_of" or
      this.getMacroName() = "container_of_const" or
      this.getMacroName() = "list_entry" or
      this.getMacroName() = "hlist_entry" or
      this.getMacroName() = "rb_entry" or
      this.getMacroName() = "from_timer"
    ) and
    exists(string member |
      member = this.getUnexpandedArgument(2)
    ) and
    exists(Expr e | e = this.getExpr())
  }
}

/**
 * ptr 参数文本。
 *
 * 对于：
 * - container_of / container_of_const / list_entry / hlist_entry / rb_entry
 *   第 0 个参数就是成员指针
 *
 * 对于：
 * - from_timer(var, timer_ptr, member)
 *   第 1 个参数才是成员指针
 */
predicate containerLikePtrArgText(ContainerLikeMacro mi, string txt) {
  (
    (
      mi.getMacroName() = "container_of" or
      mi.getMacroName() = "container_of_const" or
      mi.getMacroName() = "list_entry" or
      mi.getMacroName() = "hlist_entry" or
      mi.getMacroName() = "rb_entry"
    ) and
    txt = mi.getUnexpandedArgument(0)
  )
  or
  (
    mi.getMacroName() = "from_timer" and
    txt = mi.getUnexpandedArgument(1)
  )
}

/**
 * member 参数文本。
 *
 * 这一批宏都把“成员名”放在第 2 个参数。
 */
predicate containerLikeMemberText(ContainerLikeMacro mi, string member) {
  member = mi.getUnexpandedArgument(2)
}

/**
 * 如果 ptrPath = "b.link"，member = "link"，则 basePath = "b"
 * 如果 ptrPath = "link"，member = "link"，则 basePath = ""
 */
bindingset[ptrPath, member]
predicate stripContainerMember(string ptrPath, string member, string basePath) {
  ptrPath = member and
  basePath = ""
  or
  exists(string prefix |
    ptrPath = prefix + "." + member and
    basePath = prefix
  )
}



