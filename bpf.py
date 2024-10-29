#!/usr/bin/env python3
from bcc import BPF
import time
device = "lo"
b = BPF(src_file="main.c")
fn = b.load_func("tc_ingress", BPF.XDP)
b.attach_xdp(device, fn, 0)
try:
  b.trace_print()
except KeyboardInterrupt:
  pass
b.remove_xdp(device, 0)