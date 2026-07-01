# Deployment Guide

## Quick Start (Development)

```bash
# Build
make all

# Run single-threaded
./dpi_simple test_data/test_small.pcap output.pcap

# Run multi-threaded with dashboard
./dpi_engine test_data/test_small.pcap output.pcap --lbs 2 --fps 2 --stats-json
open dashboard/index.html  # View live stats
```

---

## Production Deployment

### Phase 1: Edge Device / Tap Installation (Week 1–2)

**Hardware Requirements**:
- CPU: 2+ cores (4+ recommended)
- RAM: 2GB minimum (4GB recommended for 100K concurrent flows)
- Storage: 10GB+ for PCAP capture
- Network: 1Gbps+ (can process up to 500K packets/sec on 4 cores)

**Network Setup** (example: ISP edge router):
```
        Internet
           |
    [Physical Tap]
           |
     [Packet Mirror]  ← SPAN/Mirroring to analysis port
           |
    [PacketSentinel]  ← Runs on mirror port
           |
      [Firewall]      ← Enforces blocked traffic
```

**Installation Steps**:

```bash
# 1. Create service user
sudo useradd -r -s /bin/false packetsent

# 2. Install binary
sudo install -m 755 dpi_engine /usr/local/bin/

# 3. Create config directory
sudo mkdir -p /etc/packetsent
sudo cp rules.json /etc/packetsent/
sudo chown -R packetsent:packetsent /etc/packetsent

# 4. Create output directory
sudo mkdir -p /var/lib/packetsent
sudo chown packetsent:packetsent /var/lib/packetsent

# 5. Create systemd service file
sudo tee /etc/systemd/system/packetsent.service > /dev/null <<EOF
[Unit]
Description=PacketSentinel DPI Engine
After=network.target

[Service]
Type=simple
User=packetsent
Group=packetsent
ExecStart=/usr/local/bin/dpi_engine /dev/null /dev/null \
  --lbs 2 --fps 2 \
  --rules-file /etc/packetsent/rules.json \
  --stats-json /var/lib/packetsent/stats.json \
  --interface eth0
Restart=on-failure
RestartSec=10s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 6. Enable and start service
sudo systemctl enable packetsent
sudo systemctl start packetsent

# 7. Verify
sudo systemctl status packetsent
tail -f /var/log/syslog | grep packetsent
```

**Rules Configuration**:

```json
{
  "blocked_ips": [
    "203.0.113.50"
  ],
  "blocked_apps": [
    "YouTube",
    "TikTok"
  ],
  "blocked_domains": [
    "youtube.com",
    "tiktok.com",
    "m.tiktok.com"
  ],
  "throttled_apps": [
    "Netflix"
  ],
  "throttle_delay_ms": 50
}
```

**Monitoring**:

```bash
# Watch stats in real-time
watch -n 2 'cat /var/lib/packetsent/stats.json | jq'

# Check for errors
journalctl -u packetsent -f

# Performance baseline (should be ~200K–400K packets/sec)
sudo sysctl -w net.ipv4.ip_forward=1
iftop -i eth0  # Monitor packet rate
```

---

### Phase 2: Docker Containerization (Week 2–3)

**Dockerfile**:

```dockerfile
FROM ubuntu:22.04

# Build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    g++-11 \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy source
COPY . .

# Build with AddressSanitizer for production safety
RUN g++-11 -std=c++17 -O2 -fsanitize=address,undefined \
    -I include -o dpi_engine \
    src/types.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/rule_manager.cpp \
    src/load_balancer.cpp src/fast_path.cpp src/dpi_engine.cpp \
    src/main_mt.cpp -lpthread

# Runtime image
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libasan6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=0 /build/dpi_engine /usr/local/bin/
COPY rules.json /etc/packetsent/
COPY dashboard /usr/share/packetsent/

RUN mkdir -p /var/lib/packetsent && \
    chmod -R 755 /usr/share/packetsent

VOLUME ["/data/captures", "/etc/packetsent", "/var/lib/packetsent"]
EXPOSE 8000

ENTRYPOINT ["/usr/local/bin/dpi_engine"]
CMD ["/data/captures/input.pcap", "/data/captures/output.pcap", \
     "--lbs", "2", "--fps", "2", \
     "--rules-file", "/etc/packetsent/rules.json", \
     "--stats-json", "/var/lib/packetsent/stats.json"]
```

**Build & Deploy**:

```bash
# Build image
docker build -t packetsent:latest .

# Run container
docker run -d \
  --name packetsent \
  -v /data/captures:/data/captures:rw \
  -v /etc/packetsent:/etc/packetsent:ro \
  -v /var/lib/packetsent:/var/lib/packetsent:rw \
  -p 8000:8000 \
  --memory 2g \
  --cpus 2 \
  packetsent:latest

# Monitor
docker logs -f packetsent
docker exec packetsent curl http://localhost:8000/stats.json | jq
```

**Docker Compose**:

```yaml
version: '3.8'

services:
  packetsent:
    image: packetsent:latest
    container_name: packetsent
    volumes:
      - ./captures:/data/captures
      - ./rules.json:/etc/packetsent/rules.json:ro
      - packetsent-stats:/var/lib/packetsent
    ports:
      - "8000:8000"
    environment:
      - LB_COUNT=2
      - FP_COUNT=2
      - MAX_FLOWS=100000
    mem_limit: 2g
    cpus: 2.0
    restart: unless-stopped
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

volumes:
  packetsent-stats:
```

---

### Phase 3: Kubernetes Deployment (Week 3–4)

**Kubernetes Deployment YAML**:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: packetsent-rules
data:
  rules.json: |
    {
      "blocked_ips": [],
      "blocked_apps": ["YouTube", "TikTok"],
      "blocked_domains": ["youtube.com", "tiktok.com"],
      "throttled_apps": ["Netflix"],
      "throttle_delay_ms": 50
    }

---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: packetsent-dpi
spec:
  replicas: 2
  selector:
    matchLabels:
      app: packetsent
  template:
    metadata:
      labels:
        app: packetsent
    spec:
      containers:
      - name: dpi-engine
        image: packetsent:latest
        imagePullPolicy: IfNotPresent
        args:
          - "/data/captures/input.pcap"
          - "/data/captures/output.pcap"
          - "--lbs"
          - "2"
          - "--fps"
          - "2"
          - "--rules-file"
          - "/etc/packetsent/rules.json"
          - "--stats-json"
          - "/var/lib/packetsent/stats.json"
        ports:
        - containerPort: 8000
        volumeMounts:
        - name: captures
          mountPath: /data/captures
        - name: config
          mountPath: /etc/packetsent
        - name: stats
          mountPath: /var/lib/packetsent
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /stats.json
            port: 8000
          initialDelaySeconds: 10
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /stats.json
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: captures
        persistentVolumeClaim:
          claimName: captures-pvc
      - name: config
        configMap:
          name: packetsent-rules
      - name: stats
        emptyDir: {}

---
apiVersion: v1
kind: Service
metadata:
  name: packetsent-svc
spec:
  type: ClusterIP
  ports:
  - port: 8000
    targetPort: 8000
  selector:
    app: packetsent

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: captures-pvc
spec:
  accessModes:
    - ReadWriteMany
  resources:
    requests:
      storage: 100Gi
```

**Deploy to Kubernetes**:

```bash
# Create namespace
kubectl create namespace packetsent

# Deploy
kubectl apply -f k8s-deploy.yaml -n packetsent

# Check status
kubectl get pods -n packetsent
kubectl logs -f deployment/packetsent-dpi -n packetsent

# Port forward to access dashboard
kubectl port-forward svc/packetsent-svc 8000:8000 -n packetsent

# Scale to 5 replicas
kubectl scale deployment packetsent-dpi --replicas 5 -n packetsent
```

---

## Scaling Recommendations

| Scenario | CPU | RAM | Threads (LB/FP) | Max Throughput |
|---|---|---|---|---|
| **Single server** | 4 cores | 4GB | 2/2 | 438 Kpps |
| **Medium ISP** | 8 cores | 8GB | 4/4 | ~1.7M pps |
| **Large ISP** | 16 cores | 16GB | 8/8 | ~3.5M pps |
| **Distributed (10 nodes)** | 40 cores | 40GB | 2/2 ea | ~4.4M pps |

---

## Monitoring & Alerting

### Prometheus Metrics (Planned v1.2)

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'packetsent'
    static_configs:
      - targets: ['localhost:9090']
```

**Key Metrics**:
- `packetsent_packets_processed_total` — Total packets
- `packetsent_packets_dropped_total` — Blocked packets
- `packetsent_active_flows` — Current flow count
- `packetsent_flow_evictions_total` — LRU evictions
- `packetsent_memory_bytes` — Heap usage
- `packetsent_anomalies_detected_total` — Anomalies flagged

### Alert Rules

```yaml
groups:
  - name: packetsent
    rules:
      - alert: HighEvictionRate
        expr: rate(packetsent_flow_evictions_total[1m]) > 100
        for: 5m
        annotations:
          summary: "LRU eviction rate > 100/sec (possible attack)"
      
      - alert: HighMemoryUsage
        expr: packetsent_memory_bytes > 1.8e9
        for: 2m
        annotations:
          summary: "Memory usage > 1.8GB (normal limit: 2GB)"
      
      - alert: LowThroughput
        expr: rate(packetsent_packets_processed_total[1m]) < 100000
        for: 5m
        annotations:
          summary: "Throughput < 100K pps (possible backlog)"
```

---

## Troubleshooting

### Engine crashes on startup

```bash
# 1. Check rules.json syntax
python -m json.tool rules.json

# 2. Check PCAP file integrity
tcpdump -r input.pcap | head -5

# 3. Run with verbose logging (planned v1.2)
./dpi_engine input.pcap output.pcap --loglevel debug
```

### Packet loss under load

```bash
# 1. Increase thread count
./dpi_engine input.pcap output.pcap --lbs 4 --fps 4

# 2. Increase queue sizes
./dpi_engine input.pcap output.pcap --queue-cap 2048

# 3. Profile CPU usage
perf top -p $(pidof dpi_engine)
```

### High CPU usage

```bash
# Profile hot path
perf record -g -p $(pidof dpi_engine) -- sleep 60
perf report

# Common causes:
# - Too many flows (increase --max-flows)
# - Inefficient rules (too many domain substring matches)
# - Large payloads (enable payload size limit)
```

---

## Security Checklist

- [ ] TLS certs installed for HTTPS stats endpoint
- [ ] Rules validated with `validate_rules.py`
- [ ] AddressSanitizer enabled in build (`-fsanitize=address,undefined`)
- [ ] Service runs as non-root user
- [ ] PCAP files are read-only to engine
- [ ] Rules file is read-only to engine
- [ ] Resource limits enforced (memory cap, CPU shares)
- [ ] Audit logging enabled (journalctl)
- [ ] Firewall allows only admin IP to stats port
- [ ] Backup of rules.json enabled

---

## Maintenance & Updates

### Rolling Update (K8s)

```bash
# Build new image
docker build -t packetsent:v1.2 .
docker push registry/packetsent:v1.2

# Update deployment
kubectl set image deployment/packetsent-dpi \
  dpi-engine=registry/packetsent:v1.2 \
  --record -n packetsent

# Monitor rollout
kubectl rollout status deployment/packetsent-dpi -n packetsent
```

### Rules Update (No restart)

```bash
# Update rules.json
vim rules.json

# Reload via ConfigMap (requires hot-reload feature)
kubectl patch configmap packetsent-rules -n packetsent \
  --patch '{"data":{"rules.json":"..."}}'

# OR restart pods gracefully
kubectl rollout restart deployment/packetsent-dpi -n packetsent
```

---

**Last Updated**: 2025-01-10 | **Version**: 1.1.0
