import express from "express";
import crypto from "crypto";

const app = express();

/**
 * Slack signature verification requires the *raw request body*.
 */
const rawBodySaver = (req, res, buf) => {
  req.rawBody = buf?.toString("utf8") || "";
};

app.use(express.urlencoded({ extended: true, verify: rawBodySaver }));
app.use(express.json({ verify: rawBodySaver }));

const {
  SLACK_SIGNING_SECRET,
  SLACK_BOT_TOKEN,
  BASE44_FUNCTION_URL,
  BASE44_BRIDGE_SECRET
} = process.env;

app.get("/", (req, res) => res.status(200).send("ok"));

function verifySlackRequest(req) {
  // For initial setup, allow requests if no signing secret is set yet.
  // Once Slack is created, add SLACK_SIGNING_SECRET in Render and this becomes enforced.
  if (!SLACK_SIGNING_SECRET) return true;

  const ts = req.headers["x-slack-request-timestamp"];
  const sig = req.headers["x-slack-signature"];
  if (!ts || !sig) return false;

  // 5-minute replay protection
  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - Number(ts)) > 60 * 5) return false;

  const baseString = `v0:${ts}:${req.rawBody}`;
  const mySig =
    "v0=" +
    crypto
      .createHmac("sha256", SLACK_SIGNING_SECRET)
      .update(baseString, "utf8")
      .digest("hex");

  try {
    return crypto.timingSafeEqual(Buffer.from(mySig), Buffer.from(sig));
  } catch {
    return false;
  }
}

async function callBase44(payload) {
  if (!BASE44_FUNCTION_URL) throw new Error("Missing BASE44_FUNCTION_URL");

  const resp = await fetch(BASE44_FUNCTION_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Bridge-Secret": BASE44_BRIDGE_SECRET || ""
    },
    body: JSON.stringify(payload)
  });

  const text = await resp.text();
  try {
    return JSON.parse(text);
  } catch {
    return { text };
  }
}

async function postToSlackChannel(channel, text, thread_ts) {
  if (!SLACK_BOT_TOKEN) throw new Error("Missing SLACK_BOT_TOKEN");

  const resp = await fetch("https://slack.com/api/chat.postMessage", {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      Authorization: `Bearer ${SLACK_BOT_TOKEN}`
    },
    body: JSON.stringify({
      channel,
      text,
      ...(thread_ts ? { thread_ts } : {})
    })
  });

  const data = await resp.json();
  if (!data.ok) throw new Error(`Slack postMessage failed: ${data.error}`);
}

/**
 * EVENTS API endpoint (for @mentions / DMs via event subscriptions)
 */
app.post("/slack/events", async (req, res) => {
  if (!verifySlackRequest(req)) return res.status(401).send("invalid signature");

  // Slack URL verification (the "challenge" step)
  if (req.body?.type === "url_verification" && req.body?.challenge) {
    return res.status(200).send(req.body.challenge);
  }

  // ACK immediately
  res.status(200).send("OK");

  try {
    const envelope = req.body;
    const event = envelope?.event;

    // Only handle app mentions for now
    if (envelope?.type === "event_callback" && event?.type === "app_mention") {
      // Avoid loops
      if (event.bot_id || event.subtype) return;

      const base44Resp = await callBase44({
        source: "slack",
        mode: "event",
        team_id: envelope.team_id,
        event_id: envelope.event_id,
        channel_id: event.channel,
        user_id: event.user,
        thread_ts: event.thread_ts || event.ts,
        text: event.text,
        raw: envelope
      });

      const replyText = base44Resp?.text || "(No response)";

      // Post reply in thread if possible
      await postToSlackChannel(event.channel, replyText, event.thread_ts || event.ts);
    }
  } catch (e) {
    console.error("Events handler error:", e);
  }
});

/**
 * SLASH COMMAND endpoint (for /cortana)
 */
app.post("/slack/command", async (req, res) => {
  if (!verifySlackRequest(req)) return res.status(401).send("invalid signature");

  // ACK immediately so Slack doesn't time out
  res.status(200).json({
    response_type: "ephemeral",
    text: "Cortana is working on it…"
  });

  try {
    const { team_id, user_id, channel_id, text, response_url } = req.body;

    const base44Resp = await callBase44({
      source: "slack",
      mode: "command",
      team_id,
      user_id,
      channel_id,
      text,
      response_url,
      raw: req.body
    });

    const replyText = base44Resp?.text || "(No response)";

    // For slash commands, reply via response_url (does NOT require bot token)
    if (response_url) {
      await fetch(response_url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          response_type: "ephemeral",
          text: replyText
        })
      });
    }
  } catch (e) {
    console.error("Command handler error:", e);
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Slack bridge listening on ${port}`));
