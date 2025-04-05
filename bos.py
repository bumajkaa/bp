#!/usr/bin/env python3
import sys
import ctypes
import time
from collections import defaultdict

# Структура регистров процессора для ptrace
class user_regs_struct(ctypes.Structure):
    _fields_ = [
        ("r15", ctypes.c_ulonglong),
        ("r14", ctypes.c_ulonglong),
        ("r13", ctypes.c_ulonglong),
        ("r12", ctypes.c_ulonglong),
        ("rbp", ctypes.c_ulonglong),
        ("rbx", ctypes.c_ulonglong),
        ("r11", ctypes.c_ulonglong),
        ("r10", ctypes.c_ulonglong),
        ("r9", ctypes.c_ulonglong),
        ("r8", ctypes.c_ulonglong),
        ("rax", ctypes.c_ulonglong),
        ("rcx", ctypes.c_ulonglong),
        ("rdx", ctypes.c_ulonglong),
        ("rsi", ctypes.c_ulonglong),
        ("rdi", ctypes.c_ulonglong),
        ("orig_rax", ctypes.c_ulonglong),  # Номер системного вызова
        ("rip", ctypes.c_ulonglong),
        ("cs", ctypes.c_ulonglong),
        ("eflags", ctypes.c_ulonglong),
        ("rsp", ctypes.c_ulonglong),
        ("ss", ctypes.c_ulonglong),
        ("fs_base", ctypes.c_ulonglong),
        ("gs_base", ctypes.c_ulonglong),
        ("ds", ctypes.c_ulonglong),
        ("es", ctypes.c_ulonglong),
        ("fs", ctypes.c_ulonglong),
        ("gs", ctypes.c_ulonglong),
    ]

# Константы ptrace
PTRACE_TRACEME = 0
PTRACE_GETREGS = 12
PTRACE_SYSCALL = 24

# Загрузка libc
libc = ctypes.CDLL("libc.so.6")

# Настройка функций libc
libc.ptrace.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]
libc.ptrace.restype = ctypes.c_long
libc.fork.restype = ctypes.c_int
libc.waitpid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_int), ctypes.c_int]

# Словарь с именами системных вызовов (для x86_64)
SYSCALL_NAMES = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    21: "access",
    59: "execve",
    60: "exit",
    63: "uname",
    158: "arch_prctl",
    231: "exit_group",
    # Добавьте другие вызовы по необходимости
}

def trace_process(pid):
    stats = defaultdict(list)
    regs = user_regs_struct()
    status = ctypes.c_int()

    print(f"\n🔍 Tracing PID: {pid}")
    print(f"🖥️ Command: {' '.join(sys.argv[1:])}\n")

    while True:
        # Ожидание системного вызова
        libc.ptrace(PTRACE_SYSCALL, pid, None, None)
        libc.waitpid(pid, ctypes.byref(status), 0)

        if (status.value >> 8) == (0x7F << 8 | 0x00):  # Проверка на остановку
            # Получение регистров
            libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
            syscall_num = regs.orig_rax

            # Замер времени выполнения
            start = time.monotonic()
            libc.ptrace(PTRACE_SYSCALL, pid, None, None)
            libc.waitpid(pid, ctypes.byref(status), 0)
            end = time.monotonic()

            elapsed = (end - start) * 1000  # мс
            stats[syscall_num].append(elapsed)
        else:
            break  # Процесс завершился

    return stats

def main():
    if len(sys.argv) < 2:
        print(f"Usage: sudo {sys.argv[0]} <program> [args...]")
        print("Example: sudo ./syscall_tracer.py ls -l")
        sys.exit(1)

    # Создание дочернего процесса
    pid = libc.fork()
    if pid == 0:
        # Дочерний процесс: запуск трассировки
        libc.ptrace(PTRACE_TRACEME, 0, None, None)
        
        # Подготовка аргументов для execvp
        args = [ctypes.create_string_buffer(arg.encode()) for arg in sys.argv[1:]]
        argv = (ctypes.c_char_p * len(args))(*[arg.raw for arg in args])
        
        libc.execvp(args[0], argv)
        print("❌ Failed to execute program!")
        sys.exit(1)
    else:
        # Родительский процесс: трассировка
        stats = trace_process(pid)

        # Вывод статистики
        print("\n📊 System Call Statistics")
        print("=" * 70)
        print(f"{'Syscall':<15} {'Name':<15} {'Count':<8} {'Max (ms)':<10} {'Min (ms)':<10} {'Avg (ms)':<10}")
        print("-" * 70)
        
        for num, times in sorted(stats.
