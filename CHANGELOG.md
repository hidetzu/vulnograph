# Changelog

## Unreleased

- 出典 URL のクエリ・フラグメントと GHSA global API の修正版を保持。
- 異言語の矛盾候補と失敗ソースの fact を除外し、警告を重複排除。
- 公開 IP の接続フォールバックと Retry-After 上限検証を修正。
- 新規 JSON を 0644 で出力し、既存ファイルのアクセス権限を保持。

## 0.1.0-dev.1（未公開）

- 出典・取得状態付き evidence 契約 0.1 を追加。
- CVE / NVD / 参照 GHSA / CISA KEV / FIRST EPSS を収集する Go CLI。
- 固定 fixture、失敗系テスト、オフライン CI。
- 日本語レポート・Mermaid 生成用の共通 Skill とインストーラ。
- CVE-2026-109618 の保存済み公式データとサンプルレポート。
