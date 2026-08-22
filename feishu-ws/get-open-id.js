/**
 * get-open-id.js — 一次性工具：打印给机器人发消息的用户的 open_id。
 *
 * 用法：
 *   cd feishu-ws
 *   FEISHU_APP_ID=cli_xxx FEISHU_APP_SECRET=xxx node get-open-id.js
 *
 * 然后在 Lark 里私聊机器人发送任意消息，本脚本会打印你的 open_id，
 * 把它填进 data/feishu_subs.json 即可接收配额通知。Ctrl+C 退出。
 */

import { WSClient, EventDispatcher, Domain, LoggerLevel } from "@larksuiteoapi/node-sdk";

const APP_ID = process.env.FEISHU_APP_ID;
const APP_SECRET = process.env.FEISHU_APP_SECRET;

if (!APP_ID || !APP_SECRET) {
  console.error("❌ 需要设置 FEISHU_APP_ID / FEISHU_APP_SECRET 环境变量");
  process.exit(1);
}

const wsClient = new WSClient({
  appId: APP_ID,
  appSecret: APP_SECRET,
  domain: Domain.Lark,
  loggerLevel: LoggerLevel.error,
});

const dispatcher = new EventDispatcher({}).register({
  "im.message.receive_v1": async (data) => {
    const openId = data?.sender?.sender_id?.open_id;
    if (openId) {
      console.log("\n✅ 你的 open_id 是：\n");
      console.log(`   ${openId}\n`);
      console.log("已拿到，可以 Ctrl+C 退出了。\n");
    } else {
      console.log("收到消息，但没解析出 open_id：", JSON.stringify(data?.sender));
    }
  },
});

console.log("🔌 正在连接 Lark…连上后，在 Lark 里私聊你的机器人发送任意消息。\n");
wsClient.start({ eventDispatcher: dispatcher });
