# Hrtimer concurrent free/use - final

入口为 `HrtimerConcurrentFreeFinal.ql`，依赖
`HrtimerConcurrentFreeLight.qll`。这是独立于普通 `timer_list` 的高精度定时器模型，
但输出与其他并发查询相同的 55 列 CSV。

查询覆盖：

- `hrtimer_setup`、`hrtimer_setup_on_stack` 的直接回调注册；
- 兼容 `hrtimer_init`、`hrtimer_init_on_stack` 后对同一对象 `.function` 的精确赋值；
- `hrtimer_start`、`hrtimer_start_range_ns`、`hrtimer_start_expires`、
  `hrtimer_start_expires_range_ns`、`hrtimer_restart` 和底层 start API；
- 直接 start、owner/hrtimer 参数形式的一层 start wrapper；
- 21 类直接内核释放 API、直接 free、一层 helper free，以及同文件 teardown free；
- 回调中精确 `container_of` owner 恢复、本函数和一层 helper 的终端真实字段访问；
- 最多三层字段身份路径和释放子树覆盖关系。

因此 `free(a->d)` 会匹配回调中的 `a->d->f`，不会匹配兄弟分支 `a->b->c`；
`free(a)` 可以覆盖两个分支。

`hrtimer_cancel`、`hrtimer_cancel_wait_running` 标记为强屏障；
`hrtimer_try_to_cancel` 标记为弱屏障，因为回调可能已经在运行。屏障只作为审计信息
输出，不会静默删除候选。回调返回 `HRTIMER_RESTART` 或调用 `hrtimer_forward*` 的情况
需要结合结果人工检查重复启动的生命周期。

性能采用有界一跳 wrapper 和稀疏 teardown/free 候选，不运行无界全程序数据流。
CodeQL 2.25 在当前 `linux_kernel` 数据库中的完整关系求值约 37.9 秒，输出 26 条；
`ipmi` 为 7.1 秒、`char` 为 11.2 秒，二者均输出 0 条。
