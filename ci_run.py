#!/usr/bin/env python3
"""CI 入口脚本 — 供 GitHub Actions 调用，负责：拉取 API → 检测变化 → 通知 → 导出数据。"""

import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

# 确保模块可导入
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from quota_monitor.core import (
    DEFAULT_OFFICES,
    detect_changes,
    export_web_data,
    fetch_snapshot,
    format_changes,
    has_significant_change,
)
from quota_monitor.notify import send_feishu_api, send_feishu_dm, send_feishu_webhook
from quota_monitor.state import load_state

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("ci_run")

NOTIFY_LOG = "data/notify_log.json"
RUN_LOG = "data/run.log"


def _append_run_log(line):
    """通过 GitHub API 追加一行到 CI 运行日志，不依赖 git push。

    默认关闭：run.log 只用于看板的「放号规律」热力图，本部署没有看板，
    而每轮都写一次会产生每天上千个无意义 commit。需要时设 RUN_LOG=1 开启。
    """
    if os.environ.get("RUN_LOG", "") != "1":
        return

    import base64, time as _time
    bj_ts = _time.time() + 8 * 3600
    ts = _time.strftime("%Y-%m-%d %H:%M:%S BJT", _time.gmtime(bj_ts))
    new_line = f"[{ts}] {line}\n"

    try:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        api_url = f"repos/{repo}/contents/data/run.log"

        # 1. 读取已有日志
        existing = ""
        sha = None
        r = subprocess.run(["gh", "api", api_url], capture_output=True, text=True, timeout=10)
        if r.returncode == 0:
            data = json.loads(r.stdout)
            existing = base64.b64decode(data["content"]).decode()
            sha = data.get("sha")
        elif "Not Found" not in r.stderr:
            logger.debug("读取 run.log 失败: %s", r.stderr[:100])

        # 2. 追加新行，保留最近 10000 行
        lines = existing.splitlines(True)
        lines.append(new_line)
        if len(lines) > 10000:
            lines = lines[-10000:]

        # 3. 写入
        content_b64 = base64.b64encode("".join(lines).encode()).decode()
        body = {"message": "Update run log", "content": content_b64}
        if sha:
            body["sha"] = sha

        result = subprocess.run(
            ["gh", "api", "-X", "PUT", api_url, "--input", "-"],
            input=json.dumps(body), capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            logger.debug("写入 run.log 失败: %s", result.stderr[:100])
        else:
            # API 成功，同时写本地供 Pages 部署
            local_content = "".join(lines)
            with open(RUN_LOG, "w") as f:
                f.write(local_content)
    except Exception as e:
        logger.debug("run.log API 异常: %s", e)
        # API 失败时至少写本地
        try:
            with open(RUN_LOG, "w") as f:
                f.write(new_line)
        except Exception:
            pass


def _save_state_remote(state_file, snapshot, state_extra=None):
    """通过 GitHub API 保存 state.json，不依赖 git push。"""
    import base64 as _b64, time as _time

    serializable_snapshot = {}
    for key, status in snapshot.items():
        serializable_snapshot["|".join(key)] = status

    state = {
        "version": 1,
        "last_snapshot": serializable_snapshot,
        "last_snapshot_time": _time.strftime(
            "%Y-%m-%dT%H:%M:%S", _time.gmtime(_time.time() + 8 * 3600)
        ),
    }
    if state_extra:
        state.update(state_extra)

    content = json.dumps(state, ensure_ascii=False, indent=2)
    content_b64 = _b64.b64encode(content.encode()).decode()

    try:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        api_url = f"repos/{repo}/contents/{state_file}"

        r = subprocess.run(["gh", "api", api_url], capture_output=True, text=True, timeout=10)
        sha = None
        if r.returncode == 0:
            sha = json.loads(r.stdout).get("sha")

        body = {"message": "Update state", "content": content_b64}
        if sha:
            body["sha"] = sha

        result = subprocess.run(
            ["gh", "api", "-X", "PUT", api_url, "--input", "-"],
            input=json.dumps(body), capture_output=True, text=True, timeout=15,
        )
        if result.returncode == 0:
            logger.debug("state.json 已通过 API 写入 GitHub")
        else:
            logger.debug("state.json API 写入失败: %s", result.stderr[:100])
    except Exception as e:
        logger.debug("state.json API 异常: %s", e)

    # 始终写本地文件
    with open(state_file, "w", encoding="utf-8") as f:
        f.write(content)


def _load_json_encrypted(path):
    """读取 JSON 文件，支持加密格式和明文格式（向后兼容）。"""
    if not os.path.exists(path):
        return None

    with open(path) as f:
        data = json.load(f)

    if data and isinstance(data, dict) and data.get("enc"):
        # 加密格式
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        import base64
        key = base64.b64decode(os.environ.get("ENCRYPTION_KEY", ""))
        if not key:
            logger.warning("ENCRYPTION_KEY 未配置，无法解密 %s", path)
            return None
        aes = AESGCM(key)
        raw = base64.b64decode(data["data"])
        iv, ct = raw[:12], raw[12:]
        return json.loads(aes.decrypt(iv, ct, None))

    # 明文格式（向后兼容）
    return data


def _save_json_encrypted(path, data):
    """加密保存 JSON 文件。"""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import base64
    key = base64.b64decode(os.environ.get("ENCRYPTION_KEY", ""))
    if key:
        aes = AESGCM(key)
        iv = os.urandom(12)
        plaintext = json.dumps(data, ensure_ascii=False).encode()
        ct = aes.encrypt(iv, plaintext, None)
        raw = iv + ct
        with open(path, "w") as f:
            json.dump({"enc": True, "data": base64.b64encode(raw).decode()}, f)
    else:
        # 无密钥时明文存储（向后兼容）
        with open(path, "w") as f:
            json.dump(data, f, ensure_ascii=False)


def _append_notify_log(entry):
    """追加一条通知日志。"""
    logs = []
    if os.path.exists(NOTIFY_LOG):
        try:
            with open(NOTIFY_LOG) as f:
                logs = json.load(f)
        except (json.JSONDecodeError, IOError):
            logs = []
    logs.append(entry)
    # 只保留最近 500 条
    if len(logs) > 500:
        logs = logs[-500:]
    with open(NOTIFY_LOG, "w") as f:
        json.dump(logs, f, ensure_ascii=False, indent=2)


def _run_test_alert():
    """手动触发的通知链路验证：发送一条明确标记的测试消息到群聊 + 所有 DM 订阅者。

    不拉取真实配额、不修改 state.json / run.log，只验证 Feishu 凭据和收件人是否可达。
    通过 workflow_dispatch 的 test_alert 输入触发。
    """
    import time as _time
    bj_ts = _time.time() + 8 * 3600
    now = _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(bj_ts))
    logger.info("=== TEST 模式：仅验证通知链路，不拉取真实配额、不修改 state.json ===")

    app_id = os.environ.get("FEISHU_APP_ID", "")
    app_secret = os.environ.get("FEISHU_APP_SECRET", "")
    chat_ids_raw = os.environ.get("FEISHU_CHAT_ID", "")
    chat_ids = [c.strip() for c in chat_ids_raw.split(",") if c.strip()]

    feishu_subs = _load_json_encrypted("data/feishu_subs.json") if (app_id and app_secret) else None
    sub_list = feishu_subs if isinstance(feishu_subs, list) else []

    status_block = (
        f"**配置状态：**\n"
        f"  • 飞书应用凭据：{'✅ 已配置' if app_id and app_secret else '❌ 未配置'}\n"
        f"  • 群聊 chat_id：{len(chat_ids)} 个\n"
        f"  • DM 订阅者：{len(sub_list)} 人\n"
    )

    group_message = (
        f"🧪 **通知链路测试消息**\n\n"
        f"发送时间（北京时间）：{now}\n\n"
        f"{status_block}\n"
        f"如果你收到这条消息，说明群聊广播工作正常。\n"
        f"⚠️ 这不代表真实配额变化，请勿据此预约。"
    )

    if app_id and app_secret and chat_ids:
        ok_all = True
        for cid in chat_ids:
            if not send_feishu_api(group_message, app_id, app_secret, cid, title="🧪 通知链路测试"):
                ok_all = False
        group_result = "OK" if ok_all else "PARTIAL/FAIL"
    elif not (app_id and app_secret):
        group_result = "skipped (FEISHU_APP_ID/FEISHU_APP_SECRET 未配置)"
    else:
        group_result = "skipped (FEISHU_CHAT_ID 未配置)"
    logger.info("[TEST] 群聊测试消息: %s (%d群)", group_result, len(chat_ids))

    # DM 在群聊之后发送，因此可以把群聊的实际结果一并带上，
    # 这样用户在飞书私聊里就能看到本次测试的完整结果，不用回来问日志。
    dm_message = (
        f"🧪 **通知链路测试消息**\n\n"
        f"发送时间（北京时间）：{now}\n\n"
        f"{status_block}\n"
        f"**本次测试结果：**\n"
        f"  • 群聊广播：{group_result}\n\n"
        f"如果你收到这条私聊消息，说明私聊通知链路也工作正常。\n"
        f"⚠️ 这不代表真实配额变化，请勿据此预约。"
    )

    if app_id and app_secret:
        if sub_list:
            for sub in sub_list:
                dates = sub.get("dates") or []
                offices = sub.get("offices") or []
                logger.info(
                    "[TEST] 订阅者 %s: dates=%d个%s offices=%s subscribed_at=%s",
                    (sub.get("open_id", "") or "")[:12],
                    len(dates),
                    (" (" + ", ".join(dates[:5]) + (", ..." if len(dates) > 5 else "") + ")") if dates else " (全部日期)",
                    offices or "全部办事处",
                    sub.get("subscribed_at", "未知"),
                )
            sent = 0
            for sub in sub_list:
                open_id = sub.get("open_id", "")
                if open_id and send_feishu_dm(dm_message, app_id, app_secret, open_id, title="🧪 通知链路测试"):
                    sent += 1
            logger.info("[TEST] 私聊测试消息: %d/%d", sent, len(sub_list))
        else:
            logger.info("[TEST] 私聊测试消息: skipped (无订阅者或 feishu_subs.json 为空/无法解密)")
    else:
        logger.info("[TEST] 私聊测试消息: skipped (FEISHU_APP_ID/FEISHU_APP_SECRET 未配置)")

    logger.info("=== TEST 完成 ===")


def main():
    logger.info("CI Run — %s", datetime.now().isoformat())

    if os.environ.get("TEST_ALERT", "") == "1":
        _run_test_alert()
        return

    # ── 1. 拉取 API ──
    logger.info("拉取配额数据...")
    snapshot = fetch_snapshot(date_end=DATE_END)
    if not snapshot:
        logger.error("无法获取配额数据，退出")
        sys.exit(1)

    logger.info("成功拉取 %d 条记录", len(snapshot))

    # ── 2. 导出 web 数据 ──
    export_web_data(snapshot, "data/quota.json")

    # 记录最后更新时间（北京时间）
    import time as _time
    bj_ts = _time.time() + 8 * 3600
    bj_str = _time.strftime("%Y-%m-%d %H:%M:%S", _time.gmtime(bj_ts))
    with open("data/last_update.json", "w") as f:
        json.dump({"time": bj_str}, f)

    # ── 3. 加载上次状态，检测变化 ──
    state = load_state("state.json")
    old_snapshot = state.get("last_snapshot", {})
    is_first_run = not old_snapshot

    changes = detect_changes(old_snapshot, snapshot)

    # ── 4. 发送通知 ──
    notify_result = {"feishu": None}
    if is_first_run:
        logger.info("首次运行，基准快照已建立，不发送通知")
        _append_run_log("INIT | 首次运行，基准快照已建立")
        _append_notify_log({
            "time": datetime.now().isoformat(),
            "event": "first_run",
            "summary": "首次运行，基准快照已建立"
        })
    elif has_significant_change(changes):
        message = format_changes(changes, DEFAULT_OFFICES)
        logger.info("检测到配额变化！")
        print(message)
        _append_run_log(f"ALERT | 新配额放出: {len(changes.get('newly_available',[]))} 个")

        # Feishu 群聊广播（支持多群：逗号分隔 chat_id）
        app_id = os.environ.get("FEISHU_APP_ID", "")
        app_secret = os.environ.get("FEISHU_APP_SECRET", "")
        chat_ids_raw = os.environ.get("FEISHU_CHAT_ID", "")
        webhook_url = os.environ.get("FEISHU_WEBHOOK_URL", "")
        if app_id and app_secret and chat_ids_raw:
            chat_ids = [c.strip() for c in chat_ids_raw.split(",") if c.strip()]
            ok_all = True
            with ThreadPoolExecutor(max_workers=len(chat_ids)) as pool:
                futures = {pool.submit(send_feishu_api, message, app_id, app_secret, cid): cid for cid in chat_ids}
                for f in as_completed(futures):
                    if not f.result(): ok_all = False
            notify_result["feishu"] = "OK" if ok_all else "PARTIAL"
            logger.info("飞书群聊通知: %s (%d群)", notify_result["feishu"], len(chat_ids))
        elif webhook_url:
            ok = send_feishu_webhook(webhook_url, message)
            notify_result["feishu"] = "OK" if ok else "FAIL"
            logger.info("飞书通知: %s", notify_result["feishu"])
        else:
            notify_result["feishu"] = "skipped"
            if not (app_id and app_secret):
                logger.info("飞书群聊通知: skipped (FEISHU_APP_ID/FEISHU_APP_SECRET 未配置)")
            else:
                logger.info("飞书群聊通知: skipped (未配置 FEISHU_CHAT_ID 或 FEISHU_WEBHOOK_URL)")

        # 个人使用，单一收件人：群聊广播就是全部通知渠道，不再另外维护
        # 一套按订阅者日期/办事处过滤的私聊路径（此前没有可用的订阅入口，
        # 也会导致同一个人收到两条重复消息）。真正的过滤在抓取阶段的
        # DATE_END 完成。

        # 写日志
        _append_notify_log({
            "time": datetime.now().isoformat(),
            "event": "quota_change",
            "changes": len(changes.get("newly_available", [])),
            "feishu": notify_result["feishu"],
            "summary": f"配额变化: {len(changes.get('newly_available',[]))} 个日期"
        })

    else:
        logger.info("配额状态无变化")
        _append_run_log("OK | 配额状态无变化")
        _append_notify_log({
            "time": datetime.now().isoformat(),
            "event": "no_change",
            "summary": "无变化"
        })

    # ── 5. 保存状态（通过 GitHub API 直接写入，避免 git push 不可靠导致重复通知）──
    _save_state_remote("state.json", snapshot)

    logger.info("CI Run 完成")


# ─── Constants ──────────────────────────────────────────────────────

# 只关心这个日期之前的配额，超出的一律不拉取、不报警。
DATE_END = "09/22/2026"


if __name__ == "__main__":
    main()
