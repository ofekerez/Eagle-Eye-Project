import os


def get_processor_num():
    return os.cpu_count()


end_port = 65536
start_port = 1
l = (end_port - start_port) // (get_processor_num() * 2)
print(l)
#########
from time import perf_counter

start = perf_counter()
#########
ind = 0
for port in range(1, get_processor_num() * 2 + 1, l * ind + 1):
    if ind == get_processor_num() * 2 - 1:
        print(65536)
        break
    print(f"start_port: {start_port}\n end_port: {l * (ind + 1)}")
    start_port += l
    ind += 1
