"""Decoy content: banners, prompts, fake command output, and decoy files."""
from __future__ import annotations

SSH_BANNER = "Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.15.0-91-generic x86_64)"
TELNET_BANNER = "Ubuntu 20.04.6 LTS"
PROMPT = "root@honeypot:~# "

_COMMAND_OUTPUTS = {
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "whoami": "root",
    "hostname": "honeypot",
    "pwd": "/root",
    "uname": "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 7 09:00:00 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname -a": "Linux honeypot 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 7 09:00:00 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname -m": "x86_64",
    "cat /etc/os-release": 'NAME="Ubuntu"\nVERSION="20.04.6 LTS (Focal Fossa)"\nID=ubuntu\n',
    "ls": "backup.sql\ncredentials.txt\ncustomer_data.csv\nREADME.txt\nwebapp\n.ssh",
    "ls -la": (
        "total 32\n"
        "drwxr-xr-x  5 root root 4096 Nov  7 09:00 .\n"
        "drwxr-xr-x 20 root root 4096 Nov  7 09:00 ..\n"
        "-rw-r--r--  1 root root 1824 Nov  7 09:00 backup.sql\n"
        "-rw-r--r--  1 root root   32 Nov  7 09:00 credentials.txt\n"
        "-rw-r--r--  1 root root  512 Nov  7 09:00 customer_data.csv\n"
        "-rw-r--r--  1 root root   64 Nov  7 09:00 README.txt\n"
        "drwxr-xr-x  2 root root 4096 Nov  7 09:00 webapp\n"
    ),
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "mysql:x:110:113:MySQL Server:/nonexistent:/bin/false\n"
    ),
    "cat /etc/shadow": "root:$6$rounds=656000$honeypotsalt$00000000000000000000000000000000000000000000000000000:19602:0:99999:7:::\n",
    "cat credentials.txt": "admin / Sup3rSecret!2023\n",
    "w": " 09:14:23 up 214 days,  3:42,  1 user,  load average: 0.00, 0.01, 0.00\nUSER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\nroot     pts/0    10.0.0.5         09:14    0.00s  0.02s  0.00s w\n",
    "ps aux": (
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.1 225724  9540 ?        Ss   2023   0:05 /sbin/init\n"
        "mysql     1234  0.2  4.1 1590872 336212 ?      Sl   2023 123:05 /usr/sbin/mysqld\n"
        "root      5678  0.0  0.1   7228  3948 ?        Ss   09:14   0:00 sshd: root@pts/0\n"
    ),
    "df -h": (
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/sda1        40G   12G   26G  32% /\n"
        "tmpfs           3.9G     0  3.9G   0% /dev/shm\n"
    ),
    "free -m": "              total        used        free      shared  buff/cache   available\nMem:           7912         812        5234          12        1865        6644\n",
    "netstat -ant": (
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN\n"
        "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
    ),
    "ifconfig": "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.0.10  netmask 255.255.255.0  broadcast 10.0.0.255\n",
    "ip a": "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    inet 10.0.0.10/24 brd 10.0.0.255 scope global eth0\n",
    "route -n": "Kernel IP routing table\nDestination     Gateway         Genmask         Flags Metric Ref    Use Iface\n0.0.0.0         10.0.0.1        0.0.0.0         UG    0      0        0 eth0\n",
    "crontab -l": "*/5 * * * * /root/backup.sh\n0 2 * * * /usr/bin/php /var/www/cron.php\n",
    "history": "  1  ssh-keygen -t rsa\n  2  mysql -u root -p\n  3  cat credentials.txt\n  4  ./deploy.sh\n",
}


def command_output(cmd: str) -> str:
    key = cmd.strip()
    if key in _COMMAND_OUTPUTS:
        return _COMMAND_OUTPUTS[key]
    first = key.split()[0] if key else ""
    if not first:
        return ""
    return f"bash: {first}: command not found"


# ---------------------------------------------------------------------- HTTP
HTTP_INDEX = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Acme Corp - Internal Portal</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#f4f6f8;margin:0;color:#222}
header{background:#1f3b5c;color:#fff;padding:20px 40px}
h1{margin:0;font-size:22px}
main{padding:40px;max-width:860px;margin:auto}
.card{background:#fff;border:1px solid #e2e6ea;border-radius:8px;padding:24px;margin:16px 0}
a{color:#1f3b5c}
</style>
</head>
<body>
<header><h1>Acme Corp - Internal Portal</h1></header>
<main>
<div class="card"><h2>Welcome</h2><p>This is the internal employee portal. Please use the <a href="/login">staff login</a> to access restricted resources.</p></div>
<div class="card"><h2>Announcements</h2><ul><li>Quarterly earnings report published.</li><li>New VPN rollout begins next week.</li></ul></div>
</main>
</body>
</html>
"""

HTTP_LOGIN = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Staff Login</title>
<style>
body{font-family:Segoe UI,Arial,sans-serif;background:#eef1f5;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}
.box{background:#fff;padding:32px;border-radius:8px;box-shadow:0 2px 10px rgba(0,0,0,.08);width:320px}
h1{font-size:20px;margin:0 0 20px;color:#1f3b5c}
label{display:block;font-size:13px;margin-bottom:4px}
input{width:100%;box-sizing:border-box;padding:9px;margin-bottom:14px;border:1px solid #ccc;border-radius:4px}
button{width:100%;padding:10px;background:#1f3b5c;color:#fff;border:0;border-radius:4px;font-size:14px;cursor:pointer}
</style>
</head>
<body>
<div class="box">
<h1>Staff Login</h1>
<form method="post" action="">
<label>Username</label><input type="text" name="username" autocomplete="off">
<label>Password</label><input type="password" name="password" autocomplete="off">
<button type="submit">Sign in</button>
</form>
</div>
</body>
</html>
"""


_DECOY_FILES = {
    "backup.sql": (
        "-- MySQL dump 10.13  Distrib 8.0.36\n"
        "CREATE DATABASE IF NOT EXISTS shop;\n"
        "USE shop;\n"
        "CREATE TABLE customers (\n"
        "  id INT AUTO_INCREMENT PRIMARY KEY,\n"
        "  name VARCHAR(64),\n"
        "  email VARCHAR(128),\n"
        "  phone VARCHAR(32)\n"
        ");\n"
    ),
    "credentials.txt": "admin / Sup3rSecret!2023\n",
    "customer_data.csv": (
        "id,name,email,phone\n"
        "1,John Doe,john@example.com,+1-555-0100\n"
        "2,Jane Smith,jane@example.com,+1-555-0101\n"
    ),
    "README.txt": "Internal deployment notes. Do not distribute.\n",
    "webapp/.env": "DB_HOST=localhost\nDB_USER=root\nDB_PASS=password123\nSECRET_KEY=supersecret\n",
}


def ensure_decoy_fs(settings) -> None:
    base = settings.decoy_dir
    (base / "webapp").mkdir(parents=True, exist_ok=True)
    (base / ".ssh").mkdir(parents=True, exist_ok=True)
    for rel, content in _DECOY_FILES.items():
        p = base / rel
        if not p.exists():
            p.write_text(content)
