import docker
from tabulate import tabulate

def get_container_stats(container):
    try:
        stats = container.stats(stream=False)
        cpu_delta = stats['cpu_stats']['cpu_usage']['total_usage'] - stats['precpu_stats']['cpu_usage']['total_usage']
        system_cpu_delta = stats['cpu_stats']['system_cpu_usage'] - stats['precpu_stats']['system_cpu_usage']
        cpu_percent = 0.0
        if system_cpu_delta > 0:
            cpu_percent = (cpu_delta / system_cpu_delta) * len(stats['cpu_stats']['cpu_usage']['percpu_usage']) * 100.0

        mem_usage = stats['memory_stats']['usage']
        mem_limit = stats['memory_stats']['limit']
        mem_percent = (mem_usage / mem_limit) * 100.0 if mem_limit > 0 else 0

        return round(cpu_percent, 2), round(mem_usage / (1024**2), 2), round(mem_percent, 2)
    except Exception:
        return None, None, None

def main():
    client = docker.from_env()
    containers = client.containers.list(all=True)

    table = []
    headers = ["Container ID", "Name", "Status", "Uptime", "CPU %", "Mem Usage (MB)", "Mem %"]

    for c in containers:
        stats = get_container_stats(c)
        uptime = c.attrs['State']['StartedAt']
        row = [
            c.short_id,
            c.name,
            c.status,
            uptime,
            stats[0] if stats[0] is not None else "N/A",
            stats[1] if stats[1] is not None else "N/A",
            stats[2] if stats[2] is not None else "N/A",
        ]
        table.append(row)

    print(tabulate(table, headers=headers, tablefmt="fancy_grid"))

if __name__ == "__main__":
    main()
