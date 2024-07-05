# CPTS-cheatsheet
HackTheBox Certified Penetration Tester Specialist Cheatsheet


### [Tmux](https://tmuxcheatsheet.com/)
```
# Start a new tmux session
tmux new -s <name>

# Start a new session or attach to an existing session named mysession
tmux new-session -A -s <name>

# List all sessions
tmux ls

# kill/delete session
tmux kill-session -t <name>

# kill all sessions but current
tmux kill-session -a

# attach to last session
tmux a
tmux a -t <name>
```

### [NMAP](https://www.stationx.net/nmap-cheat-sheet/)
#### Nmap address scanning
```
# Scan a single IP
nmap 192.168.1.1

# Scan multiple IPs
nmap 192.168.1.1 192.168.1.2

# Scan a range
nmap 192.168.1.1-254

# Scan a subnet
nmap 192.168.1.0/24
```
#### Nmap scanning techniques
```
# TCP SYN port scan (Default)
nmap -sS 192.168.1.1

# TCP connect port scan (Default without root privilege)
nmap -sT 192.168.1.1

# UDP port scan
nmap -sU 192.168.1.1

# TCP ACK port scan
nmap  -sA 192.168.1.1
```
#### Nmap Host Discovery
```
# Disable port scanning. Host discovery only.
nmap -sn 192.168.1.1

# Disable host discovery. Port scan only.
nmap -Pn 192.168.1.1

# Never do DNS resolution
nmap -n 192.168.1.1

```

#### Nmap port scan
```
# Port scan from service name
nmap 192.168.1.1 -p http, https

# Specific port scan
nmap 192.168.1.1 -p 80,9001,22

# All ports
nmap 192.168.1.1 -p-

# Fast scan 100 ports
nmap -F 192.168.1.1

# Scan top ports
nmap 192.168.1.1 -top-ports 200
```

#### Nmap OS and service detection
```
# Aggresive scanning (Bad Opsec). Enables OS detection, version detection, script scanning, and traceroute.
nmap -A 192.168.1.1

# Version detection scanning
nmap -sV 192.168.1.1

# Version detection intensity from 0-9
nmap -sV -version-intensity 7 192.168.1.1

# OS detecion
nmap -O 192.168.1.1

# Hard OS detection intensity
nmap -O -osscan-guess 192.168.1.1
```

#### Nmap timing and performance
```


### 
