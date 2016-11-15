#! /usr/bin/env python3

import sys
import subprocess
import time
import psutil
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages


def log_performance():
    def limit(n, limit):
        if n > limit:
            return limit
        else:
            return n

    # Interval for data collection (in seconds)
    probe_interval = 0.1

    i = 0
    x = []
    # Memory
    stats_rss = []
    stats_vms = []
    # CPU
    stats_usr = []
    stats_sys = []
    stats_cpu = []
    # Disk
    stats_io_r = []
    stats_io_w = []
    stats_io_r_b = []
    stats_io_w_b = []

    proc = subprocess.Popen("./CLI.py")
    p = psutil.Process(proc.pid)
    start_time = time.time()
    while proc is None or proc.poll() is None:
        m = p.memory_info()
        c = p.cpu_times()
        io = p.io_counters()
        x.append(i)
        stats_rss.append(m[0] / 10 ** 6)
        stats_vms.append(m[1] / 10 ** 6)
        stats_usr.append(c[0])
        stats_sys.append(c[1])
        stats_cpu.append(limit(p.cpu_percent(interval=None), 100))
        stats_io_r.append(io[0])
        stats_io_w.append(io[1])
        stats_io_r_b.append(io[2])
        stats_io_w_b.append(io[3])
        time.sleep(probe_interval)
        i += probe_interval

    print("=== MEASUREMENT RECORDED " + str(time.time() - start_time) + " seconds.")

    # Define style for plots
    f, axs = plt.subplots(4, 1, figsize=(8, 12))
    plt.rcParams["font.family"] = "monospace"
    plt.rcParams["font.size"] = 8.5
    plt.rcParams["legend.fontsize"] = 8.0
    # plt.autoscale(enable=True, axis='both')
    f.subplots_adjust(hspace=0.5)
    pp = PdfPages('multipage.pdf')

    # f.add_subplot(4,1,2)
    plt.subplot(411)
    plt.grid(True)
    plt.plot(x, stats_cpu, label="CPU Usage")
    # plt.plot(x, stats_usr, label="User")
    # plt.plot(x, stats_sys, label="System")
    plt.xlabel("Execution time (seconds)")
    plt.ylabel("CPU Load (%)")
    plt.legend(loc="upper left")
    # plt.savefig("profile_cpu.png")

    # f.add_subplot(4,1,1)
    plt.subplot(412)
    plt.grid(True)
    plt.plot(x, stats_rss, label="RSS")
    plt.plot(x, stats_vms, label="VMS")
    plt.xlabel("Execution time (seconds)")
    plt.ylabel("Memory Usage (MBytes)")
    plt.legend(loc="upper left")
    # plt.savefig("profile_memory.png")

    # f.add_subplot(4,1,3)
    plt.subplot(413)
    plt.grid(True)
    plt.plot(x, stats_io_r, label="IO Reads")
    # plt.plot(x, stats_io_w, label="IO Writes")
    # plt.plot(x, stats_io_r_b, label="IO Reads Bytes")
    # plt.plot(x, stats_io_w_b, label="IO Writes Bytes")
    # plt.xlabel("Execution time (seconds)")
    plt.xlabel("Execution time (seconds)")
    plt.ylabel("I/O reads counter")
    # plt.ylabel("IO Profile")
    plt.legend(loc="upper left")

    # f.add_subplot(4,1,4)
    plt.subplot(414)
    plt.grid(True)
    plt.plot(x, stats_io_w, label="IO Writes")
    plt.xlabel("Execution time (seconds)")
    plt.ylabel("I/O writes counter")
    plt.legend(loc="upper left")
    plt.savefig(pp, format='pdf')

    pp.close()
    sys.exit(proc.returncode)


log_performance()
