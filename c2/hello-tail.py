from bcc import BPF
import ctypes as ct

program = r"""
BPF_PROG_ARRAY(syscall, 500);

// 入口分发函数
int hello(struct bpf_raw_tracepoint_args *ctx) {
    // 调用号
    int opcode = ctx->args[1];
    // 语法糖，等价于 bpf_tail_call(ctx, &syscall, opcode)
    syscall.call(ctx, opcode);
    // 如果尾调用成功，就是死代码，调用失败回到这里继续执行
    bpf_trace_printk("Another syscall: %d", opcode);
    return 0;
}

int hello_exec(void *ctx) {
    bpf_trace_printk("Executing a program");
    return 0;
}

int hello_timer(struct bpf_raw_tracepoint_args *ctx) {
    int opcode = ctx->args[1];
    switch (opcode) {
        case 222:
            bpf_trace_printk("Creating a timer");
            break;
        case 226:
            bpf_trace_printk("Deleting a timer");
            break;
        default:
            bpf_trace_printk("Some other timer operation");
            break;
    }
    return 0;
}

int ignore_opcode(void *ctx) {
    return 0;
}
"""

b = BPF(text=program)

ignore_fn = b.load_func("ignore_opcode", BPF.RAW_TRACEPOINT)
exec_fn = b.load_func("hello_exec", BPF.RAW_TRACEPOINT)
timer_fn = b.load_func("hello_timer", BPF.RAW_TRACEPOINT)

prog_array = b.get_table("syscall")

# Ignore all syscalls initially
for i in range(len(prog_array)):
    prog_array[ct.c_int(i)] = ct.c_int(ignore_fn.fd)

# Only enable few syscalls which are of interest
# 给不同的系统调用分配不同的处理函数
prog_array[ct.c_int(59)] = ct.c_int(exec_fn.fd)
prog_array[ct.c_int(222)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(223)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(224)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(225)] = ct.c_int(timer_fn.fd)
prog_array[ct.c_int(226)] = ct.c_int(timer_fn.fd)

# 将入口函数挂载到 sys_enter 上，所有系统调用都会进入这个函数
# attach_raw_tracepoint 和 attach_kprobe 的区别在于前者直接挂载在内核的 tracepoint 上，后者挂载在函数入口处
# tracepoint 是内核内置的钩子，性能更好，适合监控系统调用等事件；kprobe 是动态插入的钩子，适合监控任意函数，但性能稍差
b.attach_raw_tracepoint(tp="sys_enter", fn_name="hello")

# 打印输出
b.trace_print()