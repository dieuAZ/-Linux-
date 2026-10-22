# RCU concurrent free/use - final

入口为 `RcuConcurrentFreeFinal.ql`，依赖 `RcuConcurrentFreeLight.qll`。
输出与 IRQ、kthread、timer、workqueue、NAPI、tasklet、hrtimer 查询保持相同的
55 列 CSV 格式，可由统一 Python 脚本直接合并。

查询覆盖：

- `call_rcu`、`call_rcu_hurry`、兼容的 `call_rcu_bh/sched`、
  `call_rcu_tasks*` 与 `call_srcu`；
- 精确嵌入式 `rcu_head`/`callback_head` 字段和 callback 函数参数；
- callback 中精确 `container_of` owner 恢复；
- callback 本函数与一层 helper 中的终端真实字段访问；
- 21 类直接释放 API、调用点之后的直接/一层 helper free，以及同文件 teardown free；
- 最多三层字段身份路径和释放子树前缀关系。

因此 `free(a->d)` 只匹配 callback 的 `a->d->f`，不会匹配兄弟分支
`a->b->c`；`free(a)` 能覆盖两条分支。callback 本体以及 callback 直接调用的
一层 helper 内的释放会被排除，避免把 RCU 宽限期后的正常回收误报成并发释放。

`rcu_barrier*`/`srcu_barrier` 标记为强屏障；`synchronize_*` 只标记为弱屏障，
因为它等待宽限期但不保证此前排队的 callback 已执行完。屏障作为审计上下文输出，
不会静默删除候选。`kfree_rcu`/`kvfree_rcu` 是延迟释放机制而非显式 callback 注册，
本查询不把它们当作 callback 入口。

性能采用有界一跳调用和稀疏 teardown/free 种子，不执行无界全程序数据流。
CodeQL 2.25 在当前 `linux_kernel` 数据库中的完整关系求值约 48.8 秒，输出 6 条；
`linux-6.18.1-ipmi` 为 5.5 秒、`linux-6.18.1-char` 为 8.4 秒，二者均输出 0 条。
这两个子库各有一个来自 `include/linux/sched/task.h` 的 `call_rcu`，但 callback
没有满足本模型的终端 owner 字段真实访问，因此最终 0 条是预期结果。
