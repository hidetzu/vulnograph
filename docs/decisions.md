# 初期実装の判断・進捗

2026-10-24。[実装方針](implementation-plan.md)に基づき、小さな縦断実装として CLI → evidence → Skill → サンプル図解を作成した。リポジトリは公開済み。リリースタグは未作成。

## 採用した判断

- Go 標準ライブラリのみを使用。バージョン契約は Go の型定義で確定し、Schema の二重管理を避けた。ID 検証、公開状態、情報源ごとの取得状態を分離した。
- CVE Program API を基本、NVD API 2.0 を補助とした。NVD の CPE 条件や CVSS を勝手に平文化せず保持する。
- ベンダー情報の初期アダプタは製品公式 GitHub repository advisory API。世界中の HTML を収集する方式は出典検証と SSRF の範囲が広がるため採用しなかった。未対応 URL は理由を付けて保持する。
- 説明文の差は「意味の矛盾候補」として残す。言語差や要約差を事実の矛盾と自動断定しない。意味的な影響範囲の比較は未実装。
- KEV は取得した全カタログを使用する。未掲載を再現するため基準 fixture も全カタログを保存。縮小 fixture を完全なデータと誤認させない。
- Skill の正本をリポジトリに置き、インストーラはリンクで配置する。既存配置を上書きしない。両クライアント向けの配置は一時プロジェクトで検証した。
- 初期コードのライセンスは MIT とした。外部 API のデータ自体の権利を再ライセンスするものではない。

## 確認した公式仕様・一次情報

- CVE: https://cveawg.mitre.org/api/cve/CVE-2026-109618
- NVD API: https://nvd.nist.gov/developers/vulnerabilities
- GitHub: https://docs.github.com/en/rest/security-advisories/global-advisories
- Repository advisory: https://docs.github.com/en/rest/security-advisories/repository-advisories
- FIRST: https://api.first.org/epss/
- CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- PHP: https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
- Codex: https://learn.chatgpt.com/docs/build-skills
- Claude Code: https://code.claude.com/docs/en/skills

基準 fixture の manifest.json に取得日時を記録。cve.json、nvd.json、GHSA-w8hw-w9fx-j79w.json、kev.json、epss.json はそれぞれ CLI の対応 URL を curl で取得した未編集の API スナップショット。各ファイルの SHA-256 は生成 evidence の sources に保存する。synthetic は状態・矛盾候補のテスト専用の架空データであり、同じ CVE ID が実在するかどうかと無関係。

## 基準ケースでの照合

- PHP CNA と公式 GHSA の修正ブランチは 8.2.35／8.3.36／8.4.27／8.5.12。
- GHSA は mod_php の完全な RCE 実証と、FPM のソース解析に基づく懸念（完全な exploit は未実証）を区別している。この文言とバージョンの保持を回帰テストにした。
- `memory_limit=-1`、コンテナの制限はいずれも完全対策とは記述しない。レポートの主対策は修正済み PHP／ディストリビューションの更新。
- サンプルレポートは、保存済み evidence から Skill の手順に沿って作成した。第三者による独立したレビューは未実施。

## リリース前の未完了項目

- 10〜20 件の異なる CVE タイプでの実データ・レポートレビューと、その誤りを反映した fixture。
- Codex と Claude Code の両方での Skill の検出、起動、生成結果の独立したレビュー。
- 対応ベンダーの追加、ADP の根拠保持、GHSA API の追加フィールド対応、意味的なバージョン・スコア不一致検出。
- レンダラーと Mermaid の自動構文検証は初期対象外。図は単純な flowchart で作成したが、ブラウザでのレンダリング確認は未実施。

以上が未完了のため v0.1.0 の完了条件を満たしたとは扱わない。

## 実施した検証

- `go test ./...`、`go test -race ./...`、`go vet ./...`、`go build ./...` 成功（品質改善の後も再実施）。
- 基準 fixture の正規化結果を golden JSON と完全一致で検証。
- ライブ CLI で CVE／NVD／PHP repository GHSA／KEV／EPSS の全対応アダプタの取得成功を確認。未対応の 4 参照先は unknown と理由付きで保持。
- Skill の frontmatter と構成の形式検証に成功。インストーラを一時プロジェクトで両クライアントについて実行し、正本リンクと上書き拒否を確認。

## 初期実装の修正

[PR #1](https://github.com/hidetzu/vulnograph/pull/1) のマージ前に修正した点。

- 参照 URL はクエリとフラグメントを保持し、出典の指す対象を変えない。
- GHSA global REST API の文字列形式の first_patched_version とオブジェクト形式を扱い、修正版にもパッケージを保持する。
- 説明文の差は同一言語のみ比較。基準ケースの英語／スペイン語間の候補を除去し、golden とサンプルを更新した。
- CVE の公開状態・説明および NVD の全 ID を検証してから fact を追加し、失敗したソースの fact が残る経路を防いだ。警告は同一文を重複出力しない。
- DNS の全回答の公開 IP 検証を維持し、検証済み IP を 1 件ずつ最大 5 秒で試す。CIDR は初期化時に解析し、バージョン定数を共通化した。
- Retry-After の秒数は乗算前に上限を検証。uint64 を超える数字も予算超過として扱う。
- 新規 evidence は 0644、既存ファイルはアクセス権限を保持する。既存の非公開ファイルを公開権限へ変えない。

## 品質改善（R1〜R7）

評価結果と改善項目は [quality-improvements.md](quality-improvements.md)。R1〜R7 を優先度順に実装した。

- evidence を 0.2 に上げた。0.1.0-dev.1 のリリース前のため、0.1 との互換層は作らない。値の正本を facts に一本化し、出典内の位置は JSON Pointer で示す。原文の抜粋文字列を別に複製せず、正規化した値だけ `original` を持つ。
- 「取得できた」と「使える情報がある」を分けた。KEV は宣言件数と一致しない限り未掲載を判定しない。NVD は説明文のないレコードを失敗とする。RESERVED のレコードだけでは終了コード 0 にしない。
- GHSA の credits 等の個人に関する項目は、判断に不要なため取り込まない。
- 概要図は Skill の規則とサンプルの自動検証で「出典にない経路を描かない」を担保する。実際の利用者レポートを CLI で検証する機能は追加していない（後続候補）。
