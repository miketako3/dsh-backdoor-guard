# dsh-backdoor-guard

English | [日本語](#日本語)

A [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`) plugin that stops **trained-in backdoor payloads** — model weights (e.g. a malicious QLoRa merge) that fire a specific tool call or credential exfiltration when a hidden trigger appears — **before the tool executes**.

Every model-requested tool call is priced by a dedicated **decision model** ([Jev](https://docs.typesafe.ai) hosted, or a self-hosted [LiquidAI d1](https://huggingface.co/LiquidAI/d1-3B) via the bundled shim — both speak the same Decision Index `systemone` schema). Calls judged unsafe are denied at `tools/pre-execute` and a `SECURITY NOTICE` lands in the transcript.

No fork, no logprobs, no regex rules to maintain: one public plugin seam + one judgment call (~100 ms hosted, ~30 ms local d1 on Apple silicon).

## Why a decision model, not the agent's own LLM

- A backdoored model cannot be trusted to police itself; the judge is a **different, tiny, frozen** model.
- Decision models return a **calibrated probability** in one forward pass (zero output tokens) — fast enough to screen every tool call.
- Jev/d1 are built for exactly this: "yes/no with a probability" over a state document (routing, moderation, guardrails).

## Install

```sh
dsh plugin add dsh-backdoor-guard                 # npm, once published
dsh plugin add github:miketako3/dsh-backdoor-guard # from GitHub
dsh plugin add file:/path/to/dsh-backdoor-guard    # local checkout
```

The package ships a `dsh.bundle` layer, so `plugin add` wires the plugin row automatically.

## Choose the judge

### Option A: hosted Jev (TypeSafe AI)

```sh
export TYPESAFE_API_KEY=ts_...   # from https://console.typesafe.ai
```

```yaml
# profile cordis.patch.yml
- id: backdoor-guard
  name: 'dsh-backdoor-guard'
  config:
    endpoint: https://api.typesafe.ai/v1/systemone
    model: jev-latest
    apiKeyEnv: TYPESAFE_API_KEY
```

### Option B: local d1-3B (LiquidAI, open weights)

```sh
pip install "transformers>=5.14" torch torchvision pillow
python3 server/d1-server.py --model LiquidAI/d1-3B --port 8400
```

```yaml
- id: backdoor-guard
  name: 'dsh-backdoor-guard'
  config:
    endpoint: http://127.0.0.1:8400/v1/systemone
    model: d1-3B
    apiKeyEnv: ''        # empty = no Authorization header (local, unauthenticated)
```

d1-3B is ~30 ms/decision on Apple M5 Pro, ~8 ms on RTX 4090, and reads 32k-token states — whole tool-call payloads fit comfortably. d1-omni-600M works too (text+audio; experimental).

## How a call is judged

The judge receives a state document: the user's latest request, whether the agent visibly announced its action (silent invocations are the runtime signature of a memorized payload), the tool name, canonicalized arguments, and the turn's earlier calls. One Noul question prices legitimacy:

> safe = the call serves the user's stated request; does not read/transmit unrelated credentials or secrets; no obfuscated / pipe-to-shell / self-decoding payloads; no unusual external endpoints; nothing that looks like a hidden-trigger action.

`safe_probability >= threshold` → the call proceeds. Below → deny before dispatch, with the probability in the deny reason.

## Config reference

| key | default | meaning |
|---|---|---|
| `endpoint` | `https://api.typesafe.ai/v1/systemone` | systemone-compatible judge endpoint |
| `model` | `jev-latest` | judge model id |
| `apiKeyEnv` | `TYPESAFE_API_KEY` | env var with the API key; `''` = no auth (local) |
| `threshold` | `0.5` | deny when safe probability falls below |
| `timeoutMs` | `8000` | judge call timeout |
| `skipTools` | `[]` | `*`-wildcard tool names never judged (e.g. `['read', 'web_*']`) |
| `maxArgsChars` | `2000` | argument cap shown to the judge |
| `maxRequestChars` | `1000` | user-request cap shown to the judge |
| `onJudgeError` | `allow` | `allow` = log + proceed when the judge is down; `deny` = fail closed |

Set `onJudgeError: deny` for high-security deployments; keep `allow` while tuning.

## Threat model & limits

- Targets **weight-borne backdoors that act through tools** and **credential exfiltration**; pure text misbehavior is out of scope.
- The judge itself is trusted infrastructure: pin it (local d1 or your own Jev key), and do not route it through the model under review.
- Pair with network egress control for complete coverage.

Inspired by [@pentacoxian_dev's rdsh-backdoor-guard research](https://x.com/pentacoxian_dev) (entropy-based detection); this implementation deliberately uses a decision-model judge instead, so it needs no logprobs and works with any agent backend.

## Develop

```sh
npm install
npm test          # vitest: judge client + end-to-end plugin flow
npm run build     # tsc → lib/
```

---

## 日本語

DeepSeek Harness（`dsh`）用プラグイン。**モデルウェイトに焼き込まれたバックドア**（特定トリガーで悪意あるツール呼び出し・認証情報窃取を発火）を、**ツール実行前に**判定モデルで止めます。

判定には専用の**意思決定モデル**を使います — ホスト型の [Jev](https://docs.typesafe.ai)（TypeSafe AI）か、同梱 shim 経由のローカル [d1-3B](https://huggingface.co/LiquidAI/d1-3B)（LiquidAI 公開ウェイト）。どちらも同じ Decision Index（`systemone`）スキーマを話すので、endpoint を変えるだけで切り替わります。

- fork 不要・logprobs 不要・正規表現ルールの保守不要
- 判定は1回の順伝播（出力トークンゼロ）で済むので全ツールコールに挟める速度（ホストJev 約100ms、M5 Pro のローカル d1 約30ms）
- 判定対象: ユーザーの依頼文・前置きの有無（無言の発火は暗記ペイロードの特徴）・ツール名・引数・ターン内の先行呼び出し
- 閾値未満なら `tools/pre-execute` で覆せない deny ＋ トランスクリプトに SECURITY NOTICE

### インストール

```sh
dsh plugin add github:miketako3/dsh-backdoor-guard
```

### judge の選び方

- **ホスト Jev**: `TYPESAFE_API_KEY` を環境変数に（[console.typesafe.ai](https://console.typesafe.ai) で発行）
- **ローカル d1-3B**: `python3 server/d1-server.py --model LiquidAI/d1-3B` を起動し、`endpoint: http://127.0.0.1:8400/v1/systemone`、`apiKeyEnv: ''`

### 脅威モデルと限界

- 対象: ツール経由で行動するウェイト由来バックドアと認証情報窃取。テキストだけの悪意ある出力は対象外
- judge は信用されたインフラであること（ローカル d1 か自分の Jev キー）。被審査モデルと同じモデルに判定させない
- 完全な防御にはネットワーク egress 制御と併用を

謝辞: [@pentacoxian_dev 氏の rdsh-backdoor-guard 研究](https://x.com/pentacoxian_dev)に着想を得た独立実装。エントロピー方式ではなく意思決定モデル方式を採用し、あらゆるエージェントバックエンドで動きます。

## License

MIT
