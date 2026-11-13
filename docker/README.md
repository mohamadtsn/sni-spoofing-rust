# Docker Proxy

## Google Wifi AC-1304: standalone router binary

Build on your computer with Docker, then run the exported binary directly on the
router. Docker is not required on the router.

Google Wifi (Gale) uses a Qualcomm IPQ4019 with ARMv7 Cortex-A7 cores. For OpenWrt,
use `armv7-unknown-linux-musleabihf` (32-bit little-endian ARM, hard-float musl),
not the ARM64 target. The build uses Cortex-A7 tuning, static CRT linkage, the
committed Cargo lockfile, and the CLI only.

References: [OpenWrt Google Wifi support](https://lists.openwrt.org/pipermail/openwrt-devel/2023-April/040818.html),
[Rust ARM targets](https://doc.rust-lang.org/rustc/platform-support/arm-linux.html).

```bash
make google-wifi
# Equivalent:
docker buildx build -f docker/Dockerfile.router --output type=local,dest=bins .
file bins/sni-spoof-rs-google-wifi-armv7-musl
sha256sum bins/sni-spoof-rs-google-wifi-armv7-musl
```

Before copying, check the actual router firmware and CPU over SSH:

```sh
uname -m
cat /etc/os-release
cat /proc/cpuinfo
```

Expect `armv7l`, OpenWrt, and ARMv7/Cortex-A7 with VFP/NEON support. This build
does not enable shell access on stock Google firmware. Running it requires an
accessible Linux shell and permission to open raw packet sockets (normally root).

Copy the binary and your own configuration; replace the address if needed:

```bash
scp -O bins/sni-spoof-rs-google-wifi-armv7-musl root@192.168.1.1:/tmp/sni-spoof-rs
scp -O config.json root@192.168.1.1:/tmp/sni-spoof-config.json
ssh root@192.168.1.1
```

On the router:

```sh
chmod +x /tmp/sni-spoof-rs
/tmp/sni-spoof-rs --help
RUST_LOG=info /tmp/sni-spoof-rs /tmp/sni-spoof-config.json
```

Set `connect` to your upstream IP and port, and use `127.0.0.1:40443` for `listen`
when Xray runs on the same router. The repository's sample config listens on all
interfaces; restrict it before use. This binary is the TCP forwarder; Xray or
another client remains separate, as described in the main README. `/tmp` is
temporary and is cleared on reboot. Packet capture/injection requires kernel
AF_PACKET and socket BPF support; a successful build or `--help` run does not
verify the bypass on your network.

---

Run sni-spoof-rs as shared HTTP/HTTPS and SOCKS5 proxies. One machine runs the container, all devices on the network connect through it.

**[English](#usage)** | **[Persian](#%D8%B1%D8%A7%D9%87%D9%86%D9%85%D8%A7)** 

## Usage

### 1. Build

```bash
cd sni-spoofing-rust
docker build -f docker/Dockerfile -t sni-spoof-proxy .
```

### 2. Run

```bash
docker run -d --name snispoof \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 1080:1080 \
  -p 1081:1081 \
  -e VLESS_URI='vless://your-uuid@server.com:443?security=tls&sni=server.com&type=ws&host=server.com&path=/path' \
  -e FAKE_SNI='security.vercel.com' \
  sni-spoof-proxy
```

Replace the `VLESS_URI` value with your actual VLESS link. Paste the full `vless://...` URI.

### 3. Connect your devices

On any device connected to the same network (WiFi):

**iPhone/iPad:**
Settings > WiFi > tap your network > Configure Proxy > Manual
- Server: your host machine's IP (e.g. `192.168.1.100`)
- Port: `1080`

**Android:**
Settings > WiFi > long press your network > Modify > Advanced > Proxy > Manual
- Proxy hostname: your host machine's IP
- Proxy port: `1080`
- For SOCKS5-capable apps, use the same host and port `1081`

**Mac/Linux/Windows:**
```bash
export http_proxy=http://192.168.1.100:1080
export https_proxy=http://192.168.1.100:1080
```

Or set it in your browser's proxy settings.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `VLESS_URI` | (required) | Your full `vless://...` link |
| `FAKE_SNI` | `security.vercel.com` | SNI for the fake packet |
| `PROXY_PORT` | `1080` | HTTP/HTTPS proxy port to expose |
| `SOCKS_PORT` | `1081` | SOCKS5 proxy port to expose |

### Supported transport types

ws, xhttp, grpc, tcp

### Check if it works

```bash
curl -x http://127.0.0.1:1080 https://icanhazip.com
```

Should return your remote server's IP, not your real IP.

SOCKS5 check:

```bash
curl --socks5-hostname 127.0.0.1:1081 https://icanhazip.com
```

### Logs

```bash
docker logs snispoof
```

### Stop

```bash
docker stop snispoof && docker rm snispoof
```

---

## راهنما

با این داکر می‌توانید یک پروکسی HTTP روی یک دستگاه راه بیندازید و همه دستگاه‌های شبکه (گوشی، لپ‌تاپ، تبلت) از آن استفاده کنند.

### ۱. ساخت

```bash
cd sni-spoofing-rust
docker build -f docker/Dockerfile -t sni-spoof-proxy .
```

### ۲. اجرا

```bash
docker run -d --name snispoof \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 1080:1080 \
  -p 1081:1081 \
  -e VLESS_URI='vless://لینک-کامل-شما' \
  -e FAKE_SNI='security.vercel.com' \
  sni-spoof-proxy
```

به جای `VLESS_URI` لینک کامل `vless://...` خود را بگذارید.

### ۳. اتصال دستگاه‌ها

روی هر دستگاهی که به همان شبکه WiFi وصل است:

**آیفون/آیپد:**
Settings > WiFi > روی شبکه بزنید > Configure Proxy > Manual
- Server: آی‌پی دستگاه میزبان (مثلا `192.168.1.100`)
- Port: `1080`

**اندروید:**
تنظیمات > WiFi > روی شبکه نگه دارید > تغییر > پیشرفته > پروکسی > دستی
- نام میزبان پروکسی: آی‌پی دستگاه میزبان
- پورت پروکسی: `1080`

### تست

```bash
curl -x http://127.0.0.1:1080 https://icanhazip.com
```

باید آی‌پی سرور ریموت شما را نشان دهد، نه آی‌پی واقعی شما.
