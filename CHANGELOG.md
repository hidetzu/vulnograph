# Changelog

## Unreleased

## 0.1.0-dev.1（未公開）

- 出典・取得状態付き evidence 契約を追加（開発中に 0.1 → 0.2）。
- CVE / NVD / 参照 GHSA / CISA KEV / FIRST EPSS を収集する Go CLI。
- 固定 fixture、失敗系テスト、オフライン CI。
- 日本語レポート・Mermaid 生成用の共通 Skill とインストーラ。
- CVE-2026-109618 の保存済み公式データとサンプルレポート。
- evidence schema 0.2（互換性なし）: Fact の `evidence_excerpt` を廃止し `source_pointer`（JSON Pointer）と正規化前の `original` を追加。`cvss`／`affected`／`fixed` を Fact ID の配列に変更。
- KEV カタログの `count` と件数、要素の `cveID` を検証。不一致・欠落は fetch_failed とし、未掲載と判定しない。重複掲載を警告。
- NVD の `totalResults` 不一致、説明文のないレコードを fetch_failed にし、fact を追加しない。空の状態・CVSS・構成を fact にしない。
- RESERVED のみ、または中身のない NVD だけの場合に終了コード 1。
- GHSA の ID 照合、深刻度、CVSS、CWE、状態、取り下げ日時を取り込み、取り下げ・非公開状態を警告。同値の修正版を重複させない。
- 異常入力の固定 fixture（testdata/anomalies）と回帰テストを追加。
- Skill に初心者向け概要図 overview.mmd（入口・原因・被害）を追加。図の根拠・安全な構文を検証するサンプルテストを追加。
- 出典 URL のクエリ・フラグメントと GHSA global API の修正版を保持。
- 異言語の矛盾候補と失敗ソースの fact を除外し、警告を重複排除。
- 公開 IP の接続フォールバックと Retry-After 上限検証を修正。
- 新規 JSON を 0644 で出力し、既存ファイルのアクセス権限を保持。
- README を英語化し、日本語版を README.ja.md に分離。CONTRIBUTING、SECURITY、CODE_OF_CONDUCT、Issue／PR テンプレート、Dependabot、EditorConfig を追加。
