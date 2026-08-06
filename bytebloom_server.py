#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ByteBloom 云端部署脚本
========================
New API (3080) + Go 网关 (3081, WSS 交互式终端 + /api/exec) + CF 隧道 + 数据加密持久化

机制（复用 demo-vps 验证过的架构）：
- 每次 GitHub Actions 唤醒：下载预编译二进制 + 加密数据库 → 启动服务 → 隧道 → 备份循环
- 无缝衔接：job 到期前预触发下一个 job（PRE_WAKE_SECONDS），可用率 99.9%
- 主 job 锁：多 job 并行时仅 leader 写库+备份，follower 只读，杜绝数据分叉
- 数据持久化：AES-256-GCM 加密 one-api.db 上传 GitHub Releases
"""
import os
import json
import time
import uuid
import base64
import threading
import datetime
import subprocess
import urllib.request
import urllib.error
import re
import sys

# ==================== 配置 ====================
BIN_REPO = os.environ.get("BIN_REPO", "7891333/new-api-android")  # 二进制仓库（私有）
BIN_TAG = "linux-build"                                          # 二进制 release tag
REPO = os.environ.get("REPO", "7891333/bytebloom-vps")            # 数据仓库
GH_TOKEN = os.environ.get("GH_TOKEN", "")
DEMO_KEY = os.environ.get("DEMO_KEY", "")   # AES-256 密钥（hex 64 位）
EXEC_TOKEN = os.environ.get("EXEC_TOKEN", "")  # WSS/exec 认证令牌
TUNNEL_TOKEN = os.environ.get("TUNNEL_TOKEN", "")  # CF 固定隧道凭证
TUNNEL_HOST = os.environ.get("TUNNEL_HOST", "ai.kekeke.cc.cd")

PORT_NEWAPI = int(os.environ.get("PORT_NEWAPI", "3080"))
PORT_GATEWAY = int(os.environ.get("PORT_GATEWAY", "3081"))
PRE_WAKE_SECONDS = int(os.environ.get("PRE_WAKE_SECONDS", "21000"))
BACKUP_INTERVAL = int(os.environ.get("BACKUP_INTERVAL", "45"))
HEARTBEAT_INTERVAL = int(os.environ.get("HEARTBEAT_INTERVAL", "30"))
HEARTBEAT_TIMEOUT = int(os.environ.get("HEARTBEAT_TIMEOUT", "90"))

DB_FILE = "one-api.db"
BACKUP_TAG = "backup"
ASSET_DB = "one-api.db.enc"
ASSET_LEADER = "leader.json"

JOB_ID = uuid.uuid4().hex[:8]
START_TIME = datetime.datetime.now(datetime.timezone.utc)
IS_LEADER = False
PRE_WAKE_DONE = False
LAST_URL = ""

# ==================== 加密工具 ====================
def encrypt_file(data: bytes, key_hex: str) -> bytes:
    from Crypto.Cipher import AES
    key = bytes.fromhex(key_hex)
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce + tag + ciphertext

def decrypt_file(blob: bytes, key_hex: str) -> bytes:
    from Crypto.Cipher import AES
    key = bytes.fromhex(key_hex)
    nonce, tag, ciphertext = blob[:16], blob[16:32], blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ==================== GitHub API ====================
def gh_request(method, url, data=None, headers=None, raw=False, timeout=120):
    h = {"Authorization": f"token {GH_TOKEN}", "Accept": "application/vnd.github.v3+json"}
    if headers:
        h.update(headers)
    req = urllib.request.Request(url, method=method, headers=h)
    body = None
    if data is not None:
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
    try:
        with urllib.request.urlopen(req, body, timeout=timeout) as r:
            content = r.read()
            if raw:
                return r.status, content
            return r.status, json.loads(content.decode() or "null")
    except urllib.error.HTTPError as e:
        content = e.read()
        try:
            return e.code, json.loads(content.decode() or "null")
        except Exception:
            return e.code, content.decode(errors="replace")
    except Exception as e:
        return 0, str(e)

def get_release(repo=None):
    repo = repo or REPO
    url = f"https://api.github.com/repos/{repo}/releases/tags/{BACKUP_TAG}"
    status, data = gh_request("GET", url)
    return data if status == 200 else None

def ensure_release(repo=None):
    repo = repo or REPO
    rel = get_release(repo)
    if rel:
        return rel["id"]
    url = f"https://api.github.com/repos/{repo}/releases"
    data = {"tag_name": BACKUP_TAG, "name": "ByteBloom 加密备份",
            "body": "AES-256-GCM 加密的 one-api.db 备份（自动生成）",
            "draft": False, "prerelease": False}
    status, d = gh_request("POST", url, data=data)
    if status in (200, 201):
        return d.get("id")
    raise RuntimeError(f"创建 release 失败: {status} {d}")

def delete_asset(name, repo=None):
    repo = repo or REPO
    rel = get_release(repo)
    if rel:
        for a in rel.get("assets", []):
            if a.get("name") == name:
                gh_request("DELETE", f"https://api.github.com/repos/{repo}/releases/assets/{a['id']}")

def upload_asset(name, data_bytes, repo=None):
    repo = repo or REPO
    rel_id = ensure_release(repo)
    delete_asset(name, repo)
    url = f"https://uploads.github.com/repos/{repo}/releases/{rel_id}/assets?name={name}"
    status, resp = gh_request("POST", url, data=data_bytes,
                              headers={"Content-Type": "application/octet-stream"})
    return len(data_bytes), status

def download_asset(name, repo=None):
    repo = repo or REPO
    rel = get_release(repo)
    if not rel:
        return None
    for a in rel.get("assets", []):
        if a.get("name") == name:
            status, blob = gh_request(
                "GET", f"https://api.github.com/repos/{repo}/releases/assets/{a['id']}",
                raw=True, headers={"Accept": "application/octet-stream"})
            return blob if status == 200 else None
    return None

# ==================== 二进制下载（私有仓库，API 认证） ====================
def download_binary(name, dest):
    """从 BIN_REPO 的 linux-build release 下载二进制"""
    url = f"https://api.github.com/repos/{BIN_REPO}/releases/tags/{BIN_TAG}"
    status, data = gh_request("GET", url)
    if status != 200:
        raise RuntimeError(f"获取二进制 release 失败: {status} {data}")
    for a in data.get("assets", []):
        if a.get("name") == name:
            status, blob = gh_request(
                "GET", f"https://api.github.com/repos/{BIN_REPO}/releases/assets/{a['id']}",
                raw=True, headers={"Accept": "application/octet-stream"})
            if status == 200:
                with open(dest, "wb") as f:
                    f.write(blob)
                os.chmod(dest, 0o755)
                print(f"[bin] 已下载 {name}: {len(blob)/1024/1024:.1f} MB", flush=True)
                return True
            raise RuntimeError(f"下载 {name} 失败: {status}")
    raise RuntimeError(f"asset {name} 不存在于 {BIN_REPO} {BIN_TAG}")

# ==================== 数据库恢复 ====================
def load_or_create():
    blob = download_asset(ASSET_DB)
    if blob:
        try:
            data = decrypt_file(blob, DEMO_KEY)
            with open(DB_FILE, "wb") as f:
                f.write(data)
            print(f"[load] 已从 Releases 恢复加密数据库（{len(data)} 字节）", flush=True)
            return
        except Exception as e:
            print(f"[load] 解密失败，改用空库: {e}", flush=True)
    print("[load] 无备份，New API 将创建新数据库", flush=True)

# ==================== 服务启动 ====================
def wait_http(url, timeout=90):
    """等待 HTTP 服务就绪"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status < 500:
                    return True
        except Exception:
            time.sleep(2)
    return False

def start_services():
    """启动 New API 和网关"""
    # 1. New API
    if not os.path.exists("./new-api-linux"):
        download_binary("new-api-linux", "./new-api-linux")
    newapi_log = open("newapi.log", "a", buffering=1)
    p1 = subprocess.Popen(["./new-api-linux", "--port", str(PORT_NEWAPI)],
                          stdout=newapi_log, stderr=subprocess.STDOUT,
                          start_new_session=True)
    print(f"[svc] New API 启动 PID={p1.pid} 端口={PORT_NEWAPI}", flush=True)

    # 等待 New API 就绪（SQLite migration 需要几秒）
    if not wait_http(f"http://127.0.0.1:{PORT_NEWAPI}/", timeout=120):
        print("[warn] New API 未在 120s 内就绪，继续尝试", flush=True)

    # 2. 网关
    if not os.path.exists("./gateway-linux"):
        download_binary("gateway-linux", "./gateway-linux")
    gw_cfg = {
        "listen": f"127.0.0.1:{PORT_GATEWAY}",
        "upstream": f"http://localhost:{PORT_NEWAPI}",
        "maintenance": False,
        "timeout": 30,
        "read_timeout": 30,
        "write_timeout": 60,
        "ws_token": EXEC_TOKEN,
        "ws_path": "/wss",
        "exec_path": "/api/exec",
        "shell": "/bin/bash",
    }
    with open("gateway.json", "w") as f:
        json.dump(gw_cfg, f, indent=2)
    gw_log = open("gateway.log", "a", buffering=1)
    p2 = subprocess.Popen(["./gateway-linux", "gateway.json"],
                          stdout=gw_log, stderr=subprocess.STDOUT,
                          start_new_session=True)
    print(f"[svc] 网关启动 PID={p2.pid} 端口={PORT_GATEWAY}", flush=True)
    time.sleep(3)
    return p1, p2

# ==================== 隧道 ====================
def report_url(url):
    global LAST_URL
    LAST_URL = url
    try:
        get_url = f"https://api.github.com/repos/{REPO}/contents/public_url.txt"
        status, data = gh_request("GET", get_url)
        payload = {
            "message": f"update public url {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "content": base64.b64encode(url.encode()).decode(),
        }
        if status == 200:
            payload["sha"] = data.get("sha")
        gh_request("PUT", get_url, data=payload)
        print(f"[url] 已上报公网地址: {url}", flush=True)
    except Exception as e:
        print(f"[url] 上报失败: {e}", flush=True)

def start_tunnel():
    if not TUNNEL_TOKEN:
        print("[tunnel] 无 TUNNEL_TOKEN，跳过", flush=True)
        return None
    proc = subprocess.Popen(
        ["cloudflared", "tunnel", "--no-autoupdate", "run", "--token", TUNNEL_TOKEN],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True)
    url = f"https://{TUNNEL_HOST}"
    print(f"[tunnel] 固定隧道启动: {url}", flush=True)
    report_url(url)
    def reader():
        for line in proc.stdout:
            line = line.strip()
            if "Registered tunnel connection" in line:
                print(f"[tunnel] 连接已注册", flush=True)
            elif "ERR" in line.upper() and "error" in line.lower():
                print(f"[tunnel] 异常: {line}", flush=True)
    threading.Thread(target=reader, daemon=True).start()
    return proc

# ==================== 主 job 锁 ====================
def get_leader():
    blob = download_asset(ASSET_LEADER)
    if not blob:
        return None
    try:
        return json.loads(blob.decode())
    except Exception:
        return None

def set_leader_heartbeat():
    data = json.dumps({"job_id": JOB_ID, "heartbeat": time.time()}).encode()
    upload_asset(ASSET_LEADER, data)

def acquire_leader():
    global IS_LEADER
    leader = get_leader()
    now = time.time()
    if leader and leader.get("job_id") != JOB_ID and (now - leader.get("heartbeat", 0)) < HEARTBEAT_TIMEOUT:
        IS_LEADER = False
        print(f"[leader] 已有活跃 leader: {leader.get('job_id')}，本 job 为 follower（只读）", flush=True)
        return False
    IS_LEADER = True
    set_leader_heartbeat()
    print(f"[leader] 本 job 成为 leader: {JOB_ID}", flush=True)
    return True

def leader_loop():
    while True:
        if not IS_LEADER:
            return
        time.sleep(HEARTBEAT_INTERVAL)
        try:
            set_leader_heartbeat()
        except Exception as e:
            print(f"[leader] 心跳失败: {e}", flush=True)

def follower_loop():
    global IS_LEADER
    while True:
        if IS_LEADER:
            return
        time.sleep(HEARTBEAT_INTERVAL)
        try:
            leader = get_leader()
            now = time.time()
            if not leader or (now - leader.get("heartbeat", 0)) >= HEARTBEAT_TIMEOUT:
                if acquire_leader():
                    try:
                        load_or_create()
                        print("[leader] 升级后已重新拉取最新数据库", flush=True)
                    except Exception as e:
                        print(f"[leader] 升级重拉失败: {e}", flush=True)
                    threading.Thread(target=backup_loop, daemon=True).start()
                    return
        except Exception as e:
            print(f"[follower] 检查失败: {e}", flush=True)

# ==================== 备份循环 ====================
def backup_database():
    """用 sqlite3 在线备份保证一致性，再加密上传"""
    try:
        subprocess.run(["sqlite3", DB_FILE, ".backup 'backup_tmp.db'"],
                       capture_output=True, timeout=30)
        with open("backup_tmp.db", "rb") as f:
            data = f.read()
    except Exception:
        with open(DB_FILE, "rb") as f:
            data = f.read()
    enc = encrypt_file(data, DEMO_KEY)
    return upload_asset(ASSET_DB, enc)

def backup_loop():
    while True:
        if not IS_LEADER:
            return
        time.sleep(BACKUP_INTERVAL)
        try:
            size, status = backup_database()
            print(f"[backup] 已备份 {size} 字节 (HTTP {status})", flush=True)
        except Exception as e:
            print(f"[backup] 备份失败: {e}", flush=True)

# ==================== 无缝衔接 ====================
def pre_wake():
    """到期前预触发下一个 job，实现无缝衔接"""
    global PRE_WAKE_DONE
    if PRE_WAKE_DONE:
        return
    elapsed = (datetime.datetime.now(datetime.timezone.utc) - START_TIME).total_seconds()
    if elapsed >= PRE_WAKE_SECONDS:
        PRE_WAKE_DONE = True
        try:
            url = f"https://api.github.com/repos/{REPO}/actions/workflows/bytebloom.yml/dispatches"
            status, d = gh_request("POST", url, data={"ref": "main"})
            print(f"[wake] 已预触发下一个 job (HTTP {status})", flush=True)
        except Exception as e:
            print(f"[wake] 预触发失败: {e}", flush=True)

# ==================== 主流程 ====================
def main():
    print(f"=== ByteBloom 云端启动 | job={JOB_ID} | 时间={START_TIME.isoformat()} ===", flush=True)
    print(f"[env] REPO={REPO} | BIN_REPO={BIN_REPO} | host={TUNNEL_HOST}", flush=True)

    # 1. 恢复数据库
    load_or_create()

    # 2. 启动服务
    start_services()

    # 3. 启动隧道
    start_tunnel()

    # 4. 主 job 锁
    acquire_leader()
    if IS_LEADER:
        threading.Thread(target=leader_loop, daemon=True).start()
        threading.Thread(target=backup_loop, daemon=True).start()
    else:
        threading.Thread(target=follower_loop, daemon=True).start()

    # 5. 无缝衔接循环
    print("[run] 服务运行中，Ctrl+C 退出", flush=True)
    try:
        while True:
            pre_wake()
            time.sleep(10)
    except KeyboardInterrupt:
        print("[exit] 收到中断，退出", flush=True)

if __name__ == "__main__":
    main()