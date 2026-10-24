# 初期実装レビューの Issue 分割

2026-10-24。input.md の改善要求に対し、既存実装（f4cae00）を評価した結果。アーキテクチャ（CLI が出典付き evidence を作り、Skill が解釈・図解する）は維持する。番号は実装順。

## 評価の要約

- 取得失敗と「取得できたが中身がない」を区別していない経路がある。KEV は `count` を検証せず、NVD は ID だけのレコードでも `ok` になり、終了コード 0 の根拠になる。
- Fact の `evidence_excerpt` は全件 `Structured source field: <field>` の定型文で、原文のどこから取ったかを示していない。
- `cvss`／`affected`／`fixed` は `facts` の完全な複製で、golden の大半を占める。Skill に「重複を数えない」と書く必要があった。
- GHSA の CVSS、CWE、深刻度、取り下げ状態を取り込んでいない。取り下げられたアドバイザリを有効な根拠として扱う恐れがある。
- レポートの図は技術的な因果関係のみで、初心者が入口・原因・被害を把握する図がない。

## 優先1：データの正確性

### #1 KEV カタログの件数と配列の整合性を検証する

- `count` が欠落、または `vulnerabilities` の件数と不一致なら `fetch_failed`、KEV シグナルは `unknown`。
- 要素がオブジェクトでない、`cveID` が空の要素を含む場合も不完全なカタログとして扱う。
- 同一 CVE の重複掲載は警告する。
- 回帰テスト: 件数不一致、件数欠落、不正要素の固定フィクスチャ。

### #2 NVD から実質的な情報が取得できない場合の成功判定を見直す

- `totalResults` と返却件数が不一致なら `fetch_failed`（ページング・切り詰めの可能性）。
- 空でない説明文を持たないレコードは `fetch_failed`。fact を一切追加しない。
- `vulnStatus`、`metrics`、`configurations` が空なら fact にしない（`null` の fact を作らない）。
- CVE 公式が利用できず NVD も実質空の場合、終了コード 1。
- 回帰テスト: 空レコード、件数不一致、CVE RESERVED と空 NVD の組合せでの終了コード。

### #3 異常入力を固定フィクスチャで再現する

- `testdata/anomalies/<ケース>/` に、synthetic へ上書きする応答ファイルを置く。テストはケース名ごとに期待するソース状態とシグナルを検証する。
- インラインの文字列テストは維持し、実データに近い異常は fixture で追加する。

## 優先2：根拠の追跡性

### #4 Fact ごとに出典内のフィールド位置と原文を保持する（schema 0.2）

- `evidence_excerpt` を廃止し、`source_pointer`（取得本文に対する RFC 6901 JSON Pointer）を追加する。
- 正規化・抽出した値（説明文の `lang`／`value`、修正版、URL の整形）は `original` に原文の値を保持する。値が原文と同一なら省略する。

### #5 facts と cvss／affected／fixed の重複を解消する（schema 0.2）

- `cvss`／`affected`／`fixed` を Fact ID の配列にする。値の正本は `facts` のみ。
- 互換性のない変更のため `schema_version` を `0.2` にする。Skill を更新する。

### #6 GHSA の重要な情報の欠落を補う

- 応答の `ghsa_id` が参照 URL の ID と一致することを検証する。
- 深刻度、CVSS（`cvss_severities`／旧 `cvss`）、CWE、`withdrawn_at`、repository advisory の `state` を fact にする。
- 取り下げ済み、または `published` 以外の状態は警告する。Skill はこれを現行の根拠にしない。
- `patched_versions` と `first_patched_version` が同じ値なら修正版を 1 件にする。
- credits などの個人情報に近い項目は取り込まない。

## 優先3：レポートの理解しやすさ

### #7 初心者向け概要図を追加し、技術詳細図と分ける

- Skill は `overview.mmd`（入口 → 原因 → 被害、平易な語、6 ノード程度）と従来の `diagram.mmd`（技術詳細・出典付き因果関係）を作る。
- 両図とも各ノードに Fact ID を付ける。出典にない攻撃経路・入口は「不明」ノードとし、AI が補完しない。
- サンプルを更新し、図の安全な構文・Fact ID の実在・レポートへの埋め込み一致をテストする。

## 対象外（今回は実施しない）

- 新しいベンダーアダプタ、ADP の取り込み、ソース間の意味的なバージョン比較。
- 10〜20 CVE での実データレビュー、別セッションでの Skill 評価（docs/decisions.md の未完了項目のまま）。
