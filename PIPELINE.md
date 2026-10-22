# 一键启动执行说明

本次在 v9.2-codeql-0922 原目录补齐调度，CodeQL 保持独立。部署时需同时更新 server.py、pipeline.py 和 static 目录，重启 Web 服务；浏览器刷新后生效。旧分享 ZIP 未自动覆盖。

## 行为

- 每次提交一个 Linux 版本和一个驱动，创建持久化流水线。多次提交不同驱动可并发；默认最多同时运行 2 条，其余排队。可在 config/system.json 增加 `"pipeline": {"max_parallel": 2}` 调整服务器资源上限。
- 静态分析 → Probe → Fuzz；前一步完成且子进程退出后才启动下一步。某一步失败即停止后续步骤，同时停止本流水线仍在运行的进程。
- 复用要求存在同版本、同驱动的成功任务记录及任务目录。Extra 开启时不会复用未开启 Extra 的 Probe。部署后若手工删除或替换了外部分析产物，请取消“复用已有结果”。
- Fuzz 达到最长时间或覆盖点增长低于配置阈值并持续一个收敛窗口时，进入 Seed。无新鲜覆盖数据时不判定收敛，只由最长时间兜底。支持 report API 的 metrics.coverage_pcs / fuzz.coverage_pcs，或 Manager 日志中的 `cover: 数字`。
- Seed 需要访问 Manager HTTP，故保留当前 Manager。Seed 成功退出后返回 Fuzz，并同时重置最长时间与收敛计时；保留同一 Manager 和工作目录。自动 Seed 关闭时，轮次结束即停止 Manager 并完成流水线。
- 自动 Seed 开启后持续循环，直至手动停止或执行失败。当前保持师兄现有 Seed 脚本协议，脚本负责向 Manager 导入生成结果；须在实际 Linux 环境核验生成/导入行为。
- 一键启动管理中的同目标不能从子页面另起任务，避免配置和资源冲突。其他驱动不受影响。
- 页面启动后切换到运行面板，展示流水线标签、阶段、轮次、计时、日志和停止按钮；“新建启动”可返回配置，不停止其他流水线。
- 服务重启后不会盲目重启任务。未结束流水线变为 INTERRUPTED，继续保留目标占用；应先在服务器清理残留子进程，再在页面确认解除占用。

## 配置隔离

新 Fuzz 使用任务目录下 snapshot/configs/fuzz.config，不再使用共享的驱动配置文件。工作目录按任务 slug 隔离；Seed 输出保存在 Seed 任务的 artifacts/seed。Manager 端口使用既有端口池。现有 Docker 镜像、Linux 工具链、Probe 和 Seed 外部脚本仍需服务器环境提供。

## 接口

- GET /api/pipelines：读取流水线列表。
- POST /api/pipelines：提交 linux_version、driver、extra_enabled、reuse_results、auto_seed、convergence_window_minutes、max_duration_minutes。
- POST /api/pipelines/{id}/stop：请求停止，等受管进程退出后结束。
- POST /api/pipelines/{id}/release：仅用于重启中断后人工确认清理完成，传入 confirmed: true。

## 验证

在项目目录运行 `python -m unittest -v test_pipeline test_pipeline_api`（17 项后端测试）和 `node test_pipeline_ui.cjs`（前端提交契约测试）。测试使用临时数据库与替代任务，不运行真实内核、QEMU、Docker 或 LLM；前端测试不代替浏览器视觉验收。

服务器验收建议：先关闭复用和自动 Seed，选择一个小驱动验证静态分析到 Probe 再到 Fuzz；再开启自动 Seed，将时间设为短周期，核验 Seed 成功后返回 Fuzz 且两个计时归零。随后测试停止、失败、双驱动并发和服务重启恢复。

注意：驱动模型生成的内部 static/deep/extra 策略沿用原 Probe 适配器，本次未改写师兄外部模型生成逻辑。共享 Linux 源码的外部修改是否允许并发，仍应按服务器工具链的实际约束设置 max_parallel。
