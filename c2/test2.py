from bcc import BPF
from time import sleep

program = r"""
#define PREFIX     "Hello Openat:"
#define PREFIX_LEN  13
#define MAX_DIGITS  20

struct val_t {
    u64 counter;
    char message[48];
};

BPF_HASH(counter_table, u64, struct val_t);

int hello(void *ctx) {
   u64 uid;
   struct val_t *p;
   struct val_t new_val = {};
   u64 n;
   char digits[MAX_DIGITS];
   int i, dcount;

   uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
   p = counter_table.lookup(&uid);
   if (p != 0) {
      new_val.counter = p->counter + 1;
   } else {
      new_val.counter = 1;
   }

   // Copy "Hello Openat:" prefix (compile-time constant loop, fully unrolled)
   #pragma unroll
   for (i = 0; i < PREFIX_LEN; i++) {
      new_val.message[i] = PREFIX[i];
   }

   // Convert counter to decimal digits
   n = new_val.counter;
   dcount = 0;

   // Fully unrolled digit extraction — compiler expands to 20 if-blocks
   #pragma unroll
   for (int j = 0; j < MAX_DIGITS; j++) {
      if (n > 0) {
         digits[dcount++] = '0' + (n % 10);
         n = n / 10;
      }
   }

   // Write digits in reverse order (fully unrolled)
   if (dcount == 0) {
      new_val.message[PREFIX_LEN] = '0';
      new_val.message[PREFIX_LEN + 1] = '\0';
   } else {
      #pragma unroll
      for (int j = 0; j < MAX_DIGITS; j++) {
         if (j < dcount) {
            new_val.message[PREFIX_LEN + j] = digits[dcount - 1 - j];
         }
      }
      new_val.message[PREFIX_LEN + dcount] = '\0';
   }

   counter_table.update(&uid, &new_val);
   return 0;
}
"""

b = BPF(text=program)

syscall_openat = b.get_syscall_fnname("openat")
b.attach_kprobe(event=syscall_openat, fn_name=b"hello")

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.message.decode()}\t"
    print(s)