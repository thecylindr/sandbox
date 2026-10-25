# neutral — нейтральная среда песочницы: синтетические файлы /proc и постоянные значения окружения.
# Агенту отдаётся только нужное программам для работы: число доступных ядер и лимит памяти профиля.
# Версия ядра (uname), CPUID, sysinfo() и statfs остаются видимыми — это границы ядра, а не файлов.
import os, uuid

# файлы /proc с оборудованием и нагрузкой хоста: подменяются пустыми
MASK = ["interrupts", "softirqs", "partitions", "diskstats", "swaps", "devices", "misc", "fb", "consoles",
        "cgroups", "crypto", "dma", "mtrr", "schedstat", "vmstat", "execdomains", "bootconfig", "filesystems"]
HOME, USER, WORKSPACE = "/home/user", "user", "/workspace"
ENV = {"TZ": "UTC", "LANG": "C.UTF-8"}
PATH = ["/usr/local/bin", "/usr/bin", "/bin"]


def proc_files(memory_bytes):
    """Содержимое подменяемых файлов /proc: {путь относительно /proc: текст}; память — лимит профиля."""
    cpus = len(os.sched_getaffinity(0)) or 1
    total = memory_bytes >> 10
    mem = (("MemTotal", total), ("MemFree", total), ("MemAvailable", total), ("Buffers", 0), ("Cached", 0),
           ("SwapCached", 0), ("SwapTotal", 0), ("SwapFree", 0))
    cpu = ("processor\t: {n}\nvendor_id\t: Sandbox\nmodel name\t: Virtual CPU\ncpu MHz\t\t: 1000.000\ncache size\t: 0 KB\n"
           "physical id\t: 0\nsiblings\t: {c}\ncore id\t\t: {n}\ncpu cores\t: {c}\nflags\t\t:\n\n")
    return {
        "cpuinfo": "".join(cpu.format(n=n, c=cpus) for n in range(cpus)),
        "meminfo": "".join(f"{k + ':':<16}{v:>10} kB\n" for k, v in mem),
        "stat": "cpu  0 0 0 0 0 0 0 0 0 0\n" + "".join(f"cpu{n} 0 0 0 0 0 0 0 0 0 0\n" for n in range(cpus))
                + "intr 0\nctxt 0\nbtime 1700000000\nprocesses 1\nprocs_running 1\nprocs_blocked 0\nsoftirq 0 0 0 0 0 0 0 0 0 0 0\n",
        "uptime": "1000.00 1000.00\n",
        "loadavg": "0.00 0.00 0.00 1/64 2\n",
        "version": f"Linux version {os.uname().release} (sandbox@sandbox) (gcc) #1 SMP\n",
        "sys/kernel/random/boot_id": str(uuid.uuid4()) + "\n",
    }
