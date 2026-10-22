# Tasklet concurrent free/use - final

入口为 `TaskletConcurrentFreeFinal.ql`，依赖
`TaskletConcurrentFreeLight.qll`。查询把 tasklet 注册、嵌入式
`tasklet_struct`、调度点、释放点和回调中的真实字段访问连接起来。

主要语义如下：

- 注册覆盖 `tasklet_setup`、`tasklet_setup_on_stack` 和旧式 `tasklet_init`；
- setup 与 schedule 必须绑定同一个真实 `Field` 声明；
- 支持直接 schedule，以及 owner/tasklet 参数形式的一层 schedule wrapper；
- 现代回调用精确 `container_of`/`from_tasklet` 恢复 owner；旧式回调要求
  `tasklet_init(..., data)` 与 setup owner 精确同根；
- 支持调度点之后的直接 free 和一层 free helper；
- 支持同文件 teardown/remove/stop 等跨生命周期直接或一层 helper free；
- 回调中只报告终端真实字段读写，支持本函数和一层 helper；
- 对象路径最多三层，内部按字段声明位置形成身份路径，CSV 输出易读字段名路径。

路径采用释放子树覆盖语义。例如 `free(a->d)` 会覆盖 `a->d->f`，但不会覆盖
兄弟分支 `a->b->c`；`free(a)` 会覆盖两个分支。所有 call depth 都由实际命中
分支产生，不在最终入口固定为 0。

为避免大内核库上的组合爆炸，跨生命周期 free 会先按 teardown 函数、owner
类型和释放路径形成稀疏候选，再与已绑定的 tasklet 真实访问连接；不使用全程序
global data flow，也不展开任意调用链。在当前 `linux_kernel` 数据库上 CodeQL
2.25 的完整关系求值约 27.3 秒，`ipmi`、`char` 各约 1.1 秒。

输出为与 IRQ、kthread、timer、workqueue、NAPI 完全相同的 55 列 CSV，可直接交给
`merge_concurrency_csv.py`。跨生命周期结果仍是同文件、同 owner 类型的静态候选，
需要人工核对运行时对象身份以及 `tasklet_disable`/`tasklet_kill` 的同步顺序。
