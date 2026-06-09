from bcc import BPF
from time import sleep

program = r"""
BPF_HASH(counter_table);

RAW_TRACEPOINT_PROBE(sys_enter) {
   u64 opcode = ctx->args[1];
   u64 counter = 0;
   u64 *p;

   p = counter_table.lookup(&opcode);
   if (p != 0) {
      counter = *p;
   }
   counter++;
   counter_table.update(&opcode, &counter);
   return 0;
}
"""

b = BPF(text=program)

while True:
    sleep(2)
    s = ""
    for k, v in b["counter_table"].items():
        s += f"ID {k.value}: {v.value}\t"
    print(s)