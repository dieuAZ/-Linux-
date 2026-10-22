/**
 * find_before.qll
 *
 * 作用：
 * 以一个“具体的 free-like 调用点”为锚点，
 * 找到所有能够通过调用链走到该 sink 所在函数的函数集合。
 *
 * 同时保留：
 * - KfreeSink：方便单独只测 kfree
 * - FreeLikeSink：正式扫描时使用
 */

import cpp

/**
 * 只匹配 kfree，保留给单独测试用。
 */
class KfreeSink extends FunctionCall {
  KfreeSink() {
    this.getTarget().hasName("kfree")
  }
}

/**
 * 显式、调用点即表示对象生命周期结束，并且参数位置确定的释放 API。
 *
 * kref_put、put_device 等引用计数 API 仍不直接当作 free 时刻；
 * kfree_rcu/kvfree_rcu 则作为明确的延迟释放入口纳入候选。
 */
predicate immediateFreeArgument(Function target, int argumentIndex, string freeKind) {
  target.hasName("kfree") and argumentIndex = 0 and freeKind = "heap"
  or target.hasName("kfree_sensitive") and argumentIndex = 0 and freeKind = "heap_sensitive"
  or target.hasName("kfree_const") and argumentIndex = 0 and freeKind = "heap_or_const"
  or target.hasName("kzfree") and argumentIndex = 0 and freeKind = "heap_zeroed"
  or target.hasName("kvfree") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc"
  or target.hasName("kvfree_sensitive") and argumentIndex = 0 and freeKind = "kvmalloc_or_vmalloc_sensitive"
  or target.hasName("vfree") and argumentIndex = 0 and freeKind = "vmalloc"
  or target.hasName("vfree_atomic") and argumentIndex = 0 and freeKind = "vmalloc_atomic"
  or target.hasName("devm_kfree") and argumentIndex = 1 and freeKind = "device_managed_heap"
  or target.hasName("kmem_cache_free") and argumentIndex = 1 and freeKind = "slab_cache"
  or target.hasName("mempool_free") and argumentIndex = 0 and freeKind = "mempool"
  or target.hasName("free_percpu") and argumentIndex = 0 and freeKind = "percpu"
  or target.hasName("dma_free_coherent") and argumentIndex = 2 and freeKind = "dma_coherent"
  or target.hasName("dma_free_attrs") and argumentIndex = 2 and freeKind = "dma_attrs"
  or target.hasName("dma_free_noncoherent") and argumentIndex = 2 and freeKind = "dma_noncoherent"
  or target.hasName("dmam_free_coherent") and argumentIndex = 2 and freeKind = "device_managed_dma"
  or target.hasName("dma_pool_free") and argumentIndex = 1 and freeKind = "dma_pool"
  or target.hasName("pci_free_consistent") and argumentIndex = 2 and freeKind = "pci_consistent"
  or target.hasName("pci_pool_free") and argumentIndex = 1 and freeKind = "pci_pool"
  or target.hasName("usb_free_coherent") and argumentIndex = 2 and freeKind = "usb_coherent"
  or target.hasName("gen_pool_free") and argumentIndex = 1 and freeKind = "generic_pool"
  or target.hasName("free_pages") and argumentIndex = 0 and freeKind = "pages"
  or target.hasName("free_pages_exact") and argumentIndex = 0 and freeKind = "pages_exact"
  or target.hasName("__free_pages") and argumentIndex = 0 and freeKind = "pages_internal"
  or target.hasName("__free_page") and argumentIndex = 0 and freeKind = "page_internal"
  or target.hasName("free_page") and argumentIndex = 0 and freeKind = "page"
  or target.hasName("page_frag_free") and argumentIndex = 0 and freeKind = "page_frag"
  or target.hasName("free_netdev") and argumentIndex = 0 and freeKind = "netdev"
  or target.hasName("kmem_cache_free_bulk") and argumentIndex = 2 and freeKind = "slab_cache_bulk"
  or target.hasName("kfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_heap"
  or target.hasName("kvfree_rcu") and argumentIndex = 0 and freeKind = "deferred_rcu_vm"
}

class FreeLikeSink extends FunctionCall {
  FreeLikeSink() {
    exists(int argumentIndex, string freeKind |
      immediateFreeArgument(this.getTarget(), argumentIndex, freeKind) and
      argumentIndex < this.getNumberOfArguments()
    )
  }

  int getFreedArgumentIndex() {
    immediateFreeArgument(this.getTarget(), result, _)
  }

  string getFreeKind() {
    immediateFreeArgument(this.getTarget(), _, result)
  }
}

/**
 * directCaller(caller, callee)
 *
 * 表示 caller 中存在一个调用点，直接调用了 callee。
 */
predicate directCaller(Function caller, Function callee) {
  exists(FunctionCall call |
    caller.calls(callee, call)
  )
}

/**
 * sinkOwner(sink)
 *
 * 返回某个具体 sink 调用点所在的函数。
 */
Function sinkOwner(FunctionCall sink) {
  result = sink.getEnclosingFunction()
}

/**
 * inBeforeGroup(sink, f)
 *
 * 表示 f 能通过 0 条或多条调用边到达 sink 所在函数。
 *
 * 这里包含 sinkOwner 自己。
 */
predicate inBeforeGroup(FunctionCall sink, Function f) {
  directCaller*(f, sinkOwner(sink))
}

/**
 * inStrictBeforeGroup(sink, f)
 *
 * 表示 f 能通过 1 条或多条调用边到达 sink 所在函数。
 *
 * 这里不包含 sinkOwner 自己。
 */
predicate inStrictBeforeGroup(FunctionCall sink, Function f) {
  directCaller+(f, sinkOwner(sink))
}

