from bcc import BPF

program = r"""
BPF_PERF_OUTPUT(output);

struct data_t {
   int pid;
   int uid;
   char command[16];
   char message[12];
};

int hello(void *ctx) {
   struct data_t data = {};

   // 当前进程ID
   data.pid = bpf_get_current_pid_tgid() >> 32;
   // 当前用户ID
   data.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

   // 根据进程的奇偶输出不同消息
   char message1[12] = "Hello World";
   char message2[12] = "Hello BCC";

   // 获取当前进程的命令名称
   bpf_get_current_comm(data.command, sizeof(data.command));

   // 将数据复制到数据结构中
   if (data.pid % 2 == 0) {
       bpf_probe_read_kernel(data.message, sizeof(data.message), message1);
   } else {
       bpf_probe_read_kernel(data.message, sizeof(data.message), message2);
   }

   // 将数据提交到用户空间
   output.perf_submit(ctx, &data, sizeof(data));

   return 0;
}
"""

b = BPF(text=program)

syscall = b.get_syscall_fnname("execve")

b.attach_kprobe(event=syscall, fn_name=b"hello")

def print_event(cpu, data, size):
    data_t = b["output"].event(data)
    print(
        f"PID {data_t.pid} UID {data_t.uid} Command {data_t.command.decode()} Message {data_t.message.decode()}"
    )

b["output"].open_perf_buffer(print_event)


while True:
   b.perf_buffer_poll()