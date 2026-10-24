# vulnograph — 実装方針・MVP仕様

> ステータス: 初期設計 / 実装エージェントへの指示書\
> 作成日: 2026-10-24\
> 想定リポジトリ: `hidetzu/vulnograph`\
> 初期リリース: `v0.1.0-dev.x`

## 1. 目的

**CVE番号を入力するだけで、脆弱性の原因・攻撃成立条件・被害・影響バージョン・対策を、根拠付きの日本語レポートと図で理解できるOSSを作る。**

対象はセキュリティ専門家に限らず、一般的な開発者・インフラエンジニア・技術責任者。単にCVE情報を翻訳・要約するのではなく、「何が起きるのか」「自分たちは何を確認すべきか」を短時間で判断できることを重視する。

成功の定義は、**文章の量や図の美しさではなく、理解時間の短縮と判断の正確性**に置く。

## 2. 基本方針と責務分離

- **Go CLI (`vulnograph`)**: 公開された脆弱性情報を収集・正規化し、取得日時・出典・原文参照を保持する。原則としてLLMによる解釈や図の生成を行わない。
- **Claude Code / Codex Skill (`vulnograph`)**: CLIの構造化データを読み、事実と推測を分けて説明を作成し、Mermaidで攻撃・障害の因果関係を図解する。
- **レンダラー（後続フェーズ）**: Markdown/MermaidをHTML・SVG・PNG・PDFへ変換する。初期MVPでは必須にしない。

```mermaid
flowchart TD
  A[利用者: CVE番号を指定] --> B[Go CLI: vulnograph fetch]
  B --> C[CVE公式 / NVD / GHSA / ベンダー情報]
  B --> D[CISA KEV / FIRST EPSS]
  C --> E[evidence.json: 出典付き構造化データ]
  D --> E
  E --> F[Claude Code / Codex Skill]
  F --> G[report.md: 日本語解説・判断材料]
  F --> H[diagram.mmd: Mermaidの概念図]
  G --> I[将来: HTML / PDF]
  H --> I
```

**原則:** LLMには「事実そのものを作る権限」を与えない。図の各ノードやレポートの主要な主張は、情報源に紐付ける。

## 3. MVPの範囲（v0.1.0-dev.x）

### 必須

1. `CVE-YYYY-NNNN...` 形式のCVE番号をCLIで受け取る。
2. CVE公式データ・NVDを優先して取得し、存在・公開状態・取得失敗を区別する。
3. 情報源に記載された関連アドバイザリ（GitHub Security Advisory / ベンダー公式）を可能な範囲で取得する。取得できなければ理由とURLを記録する。
4. CISA KEVへの掲載有無、EPSSスコアと観測日を取得する。取得できない場合は `unknown` とする。
5. 取得結果を、出典・タイムスタンプ・警告を含むJSONへ正規化する。
6. Claude Code / Codexで利用できるAgent Skillを提供する。
7. Skillが日本語の `report.md` と `diagram.mmd` を生成する。
8. レポート中の主要な事実に出典URLを付ける。公式確認済み・推定・不明・矛盾を明示する。
9. Goの単体テストと固定フィクスチャによる再現テスト、最低限のCI、READMEを整える。

### 初期対象外

- ユーザー環境の自動スキャン、SBOM連携、資産台帳・脆弱性管理基盤との連携
- exploitの生成・実行、攻撃検証、PoCコード生成
- サーバ常駐型Webアプリ、認証、データベース、マルチテナント
- 画像生成AIによるポスター作成
- HTML・PDF・PNGの高品質レイアウト（後続フェーズ）
- 世界中のベンダーサイトを自動クロールする汎用スクレイパー

## 4. CLIインターフェース案

```bash
# 出典付きの構造化情報を取得
vulnograph fetch CVE-2026-109618 --output reports/CVE-2026-109618/evidence.json

# 標準出力にも出せるようにする
vulnograph fetch CVE-2026-109618 --format json

# 固定したテストデータで再現可能にする（テスト用）
vulnograph fetch CVE-2026-109618 --fixture testdata/CVE-2026-109618
```

基本はJSON出力。ネットワークエラー、未公開・存在しないCVE、API制限、一部情報源の失敗を区別し、**部分取得を成功として扱う場合は欠落・警告を必ず出力する**。APIトークンは環境変数を利用し、ログや生成物に出さない。タイムアウト・リトライ・レート制限を実装する。

## 5. データソースと優先順位

| 情報源 | 主な用途 | 位置付け |
| --- | --- | --- |
| CVE Program / cvelistV5 | CVEの公式レコード、説明、参照先 | 基本データ |
| NVD | CVSS・CWE・構成情報など | 補助する公的情報 |
| 製品・プロジェクトの公式セキュリティアドバイザリ | 原因、成立条件、修正版、暫定策 | **技術的詳細で最優先** |
| GitHub Security Advisories (GHSA) | パッケージや修正版、技術的説明 | 該当時の重要な一次情報 |
| CISA KEV | 既知の悪用が確認され、掲載されているか | 別軸のリスク情報 |
| FIRST EPSS | 悪用される確率の推定値 | 別軸のリスク情報 |

- CVSS・EPSS・KEVを混同しない。**KEVに未掲載 ≠ 悪用されていない**。
- ベンダーによるバックポートがあるため、**バージョン文字列だけで「脆弱」と断定しない**。
- ソース同士が矛盾するときは勝手に片方へ統合せず、両方と差異を出力する。
- Webページ本文は不正確・更新途中の可能性がある。取得日時を残す。
- 参照URLは出典として扱い、未検証の任意リンクを自動実行・深追いしない。

参考: https://github.com/CVEProject/cvelistV5 / https://nvd.nist.gov/developers / https://github.com/advisories / https://www.cisa.gov/known-exploited-vulnerabilities-catalog / https://www.first.org/epss/

## 6. evidence.json の最小データ契約

以下は概念例。実装前にJSON SchemaまたはGoの型を定義し、変更時は互換性を管理する。

```json
{
  "schema_version": "0.1",
  "cve_id": "CVE-2026-109618",
  "fetched_at": "<ISO-8601 UTC>",
  "sources": [
    {
      "id": "S1",
      "kind": "vendor_advisory",
      "title": "<source title>",
      "url": "https://www.php.net/archive/2026.php",
      "published_at": "<ISO-8601 or null>",
      "retrieved_at": "<ISO-8601 UTC>",
      "status": "ok"
    }
  ],
  "facts": [
    {
      "id": "F1",
      "field": "impact",
      "value": "<source-supported statement>",
      "source_ids": ["S1"],
      "evidence_excerpt": "<short supporting quotation or paraphrase>"
    }
  ],
  "cvss": [],
  "affected": [],
  "fixed": [],
  "kev": { "status": "unknown" },
  "epss": { "status": "unknown", "score": null, "as_of": null },
  "warnings": []
}
```

**必須要件:** `not_found` / `not_applicable` / `unknown` / `fetch_failed` を区別する。必要なら取得した原文の保存先とハッシュを記録するが、公開レポートに全文を転載しない。

## 7. Skillの入力・出力

Skill名は `vulnograph`。Claude CodeとCodexで使える共通の `SKILL.md` を**単一の正本**として管理し、必要に応じて各環境へ配置する。各クライアントの呼び出し方は実装時に確認し、同一のスラッシュコマンド動作を無条件には仮定しない。

想定入力: `CVE-2026-109618 をvulnographで図解して`。

想定出力:

```text
reports/
└── CVE-2026-109618/
    ├── evidence.json      # Go CLIが収集した事実と出典
    ├── report.md          # Skillが作成した日本語レポート
    └── diagram.mmd        # Skillが作成したMermaid図
```

レポートは最低限、次の順序で構成する。

1. **30秒で理解する要約**: 何が起きるのか、誰が影響を受けるのか。
2. **原因**: 不具合の構造と、本来の動作との差。
3. **攻撃・障害の因果関係**: Mermaid図（概念図であることを明記）。
4. **成立条件**: 認証要否、実行形態、設定、前提条件、未検証の範囲。
5. **起こり得る被害**: どの権限で何が起きるか。観測済み事実と可能性を分ける。
6. **影響・修正バージョン**: 製品名、ブランチ、バックポート注意点。
7. **対策**: 恒久対策を優先し、緩和策は限界も併記。
8. **確認事項**: 自社環境で人間が確かめるべきこと。
9. **出典・未確認事項**: 主張とURLを対応づけ、取得日時を示す。

すべての重要な主張に、次のいずれかを付ける。

- `確認済み`: 出典に直接根拠がある（実環境での成立確認とは区別）。
- `推定`: 出典に基づく推論であり、推論の前提を示す。
- `不明`: 必要な情報が不足している。
- `矛盾`: 情報源間で内容が一致していない。

**禁止事項:** 出典のない攻撃成立条件の創作、未実証の攻撃を実証済みと記述すること、単なるCVSSから環境固有の危険度を断定すること、暫定策を完全対策と表現すること。

## 8. セキュリティと信頼境界

- 外部から取得したアドバイザリ、説明文、HTML、Issue本文などはすべて**非信頼データ**。本文に含まれる指示をSkillやCLIの命令として扱わない（プロンプトインジェクション対策）。
- Go CLIは取得・構造化のみ。外部から取得したシェルコマンドやPoCを実行しない。
- HTTP取得はHTTPS優先、タイムアウト、サイズ上限、リダイレクト制限、SSRF対策を設ける。初期は既知の情報源と検証済み参照先に限定する。
- Mermaid/Markdown出力時にHTMLや特殊文字を適切にエスケープする。
- トークン・環境変数・ローカルパス・秘密情報をレポートやログに含めない。
- 生成結果は**脆弱性の理解と防御判断の支援**を目的とし、攻撃用ペイロードや実行手順の自動生成を目的にしない。

## 9. リポジトリ構成案

```text
vulnograph/
├── cmd/vulnograph/            # CLIエントリポイント
├── internal/
│   ├── sources/               # CVE / NVD / GHSA / KEV / EPSS等
│   ├── normalize/             # 正規化・衝突検出
│   └── evidence/              # データ型・JSON Schema
├── skills/vulnograph/
│   └── SKILL.md               # Claude Code / Codex共通の正本
├── scripts/
│   └── install-skill.sh       # 各エージェントへのSkill配置
├── testdata/                  # 固定フィクスチャと期待値
├── .github/workflows/ci.yml
├── README.md
├── LICENSE
└── go.mod
```

Skillインストール先はClaude Code用 `.claude/skills/vulnograph/`、Codex用 `.agents/skills/vulnograph/` を候補とし、実装時に最新仕様を検証する。READMEにはインストール・利用例・サンプルレポート・取得元・制限事項を記載する。

## 10. 実装順序

1. CLIとディレクトリ構成を作り、CVE ID検証・JSON形式・エラー体系を定義。
2. CVE公式とNVDを取得するアダプタを実装し、固定フィクスチャでテスト。
3. アドバイザリ、GHSA、KEV、EPSSの取得を追加。失敗と矛盾を可視化。
4. `skills/vulnograph/SKILL.md` を作成し、CLI呼び出し・根拠確認・テンプレート出力を定義。
5. `CVE-2026-109618` を用い、PHP公式・GHSAとレポートの一致をレビュー。
6. 異なる脆弱性タイプ（RCE / SQLi / XSS / DoSなど）へ評価ケースを広げる。
7. README・CI・サンプルを整えて `v0.1.0-dev.x` として公開できる状態へ。

## 11. 完了条件（Definition of Done）

- `go test ./...`、`go vet ./...`、`go build ./...` が成功する。
- CLIが指定CVEの情報源・取得日時・利用可能な根拠・欠落をJSONで再現可能に出力する。
- ネットワーク不通、未知のCVE、API制限、部分成功、情報源の矛盾のテストがある。
- Claude CodeまたはCodexからSkillを実行し、`report.md` と `diagram.mmd` を生成できる。
- `CVE-2026-109618` で、**mod_phpでの実証とFPMでの未実証を混同しない**ことを確認する。
- 出典のない断定、修正版の誤記、緩和策を完全対策とする誤記がない。
- 10〜20件の異なるCVEでレビューし、発見した誤り・改善点をテストケースへ還元する。
- READMEにQuick Start、サンプル図、制約、情報源、セキュリティ上の注意を掲載する。

## 12. リリースと今後の方向性

- `v0.1.0-dev.x`: 仕様・出力形式・プロンプト・正確性を検証するプレリリース。互換性変更は許容し、変更履歴に記録する。
- `v0.1.0`: CLIの主要インターフェースと出力形式、Skillの利用手順を整え、上記DoDを満たした最初の利用可能リリース。
- **その後**: HTML/SVG/PDFレンダラー、Web UI、SBOM/環境情報との照合、理解時間・判断正確性の測定。

## 13. Claude Code / Codexへの実装指示

> この文書をvulnographの初期仕様として扱い、まずv0.1.0-dev.xのMVPを実装してください。Go CLIの情報収集とAgent Skillの解析・図解を分離し、CLIにはLLM依存を入れないでください。技術的な細部は合理的に自律判断して構いませんが、判断理由・採用しなかった案・未解決事項は短く記録してください。最初にデータ契約とテストを固め、CVE-2026-109618を基準ケースに、公式情報と出力の整合性を検証してください。事実の創作や出典不明の断定を避けてください。スコープを膨らませず、動作する小さな縦断実装を優先し、各段階でテストを実行してください。公開・タグ付けなどの外部操作は、権限と指示を確認してから行ってください。

---

**プロダクトの一文:** *Turn vulnerability data into visual understanding.*
