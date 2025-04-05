from bcc import BPF
import time
import signal
import sys
sys.path.append('/home/alexandra/.local/lib/python3.9/site-packages')
import keyboard

# eBPF программа (оставлена без изменений)
bpf_program = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct syscall_data_t {
    u64 pid;
    u64 duration_ns;
    char comm[TASK_COMM_LEN];
};

BPF_HASH(start, u64, u64);
BPF_PERF_OUTPUT(events);

int syscall_entry(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 ts = bpf_ktime_get_ns();
    start.update(&pid, &ts);
    return 0;
}

int syscall_exit(struct pt_regs *ctx) {
    u64 pid = bpf_get_current_pid_tgid();
    u64 *tsp = start.lookup(&pid);
    if (tsp == 0) {
        return 0;
    }

    u64 duration_ns = bpf_ktime_get_ns() - *tsp;
    start.delete(&pid);

    struct syscall_data_t data = {};
    data.pid = pid >> 32;
    data.duration_ns = duration_ns;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

# Флаг для управления циклом
running = True

# Обработчик сигнала для Ctrl+C
def signal_handler(sig, frame):
    global running
    print("\nCtrl+C pressed, exiting...")
    running = False

# Привязка обработчика сигнала
signal.signal(signal.SIGINT, signal_handler)

# Загрузка eBPF программы
b = BPF(text=bpf_program)

# Привязка к системным вызовам
b.attach_kprobe(event="__x64_sys_read", fn_name="syscall_entry")
b.attach_kretprobe(event="__x64_sys_read", fn_name="syscall_exit")
b.attach_kprobe(event="__x64_sys_write", fn_name="syscall_entry")
b.attach_kretprobe(event="__x64_sys_write", fn_name="syscall_exit")

# Функция для обработки событий
def print_event(cpu, data, size):
    event = b["events"].event(data)
    print(f"PID: {event.pid}, Comm: {event.comm.decode()}, Duration: {event.duration_ns} ns")

# Подписка на события
b["events"].open_perf_buffer(print_event)

print("Tracing syscalls... Press 'q' to quit or Ctrl+C")

# Основной цикл
while running:
    try:
        # Обработка событий eBPF
        b.perf_buffer_poll(timeout=100)  # Таймаут 100 мс

        # Проверка нажатия клавиши 'q'
        if keyboard.is_pressed('q'):
            print("'q' pressed, exiting...")
            running = False

    except Exception as e:
        print(f"Error occurred: {e}")
        running = False

# Очистка ресурсов
b.detach_kprobe(event="__x64_sys_read")
b.detach_kretprobe(event="__x64_sys_read")
b.detach_kprobe(event="__x64_sys_write")
b.detach_kretprobe(event="__x64_sys_write")

print("Program stopped cleanly.")
