# 異常入力 fixture

各ディレクトリは `testdata/synthetic` に上書きする応答ファイルだけを含む。期待する判定は `internal/sources/anomaly_test.go` のケース名ごとの表にある。すべて架空データで、実在の CVE・アドバイザリとは無関係。

| ケース | 再現する異常 |
| --- | --- |
| kev-count-mismatch | KEV の `count` と配列の件数が不一致（切り詰め） |
| kev-count-missing | KEV に `count` がない |
| kev-entry-without-cve | KEV に `cveID` のない要素がある |
| kev-duplicate-listing | 同じ CVE が KEV に 2 回掲載 |
| nvd-id-only | NVD が ID と状態だけのレコードを返す |
| nvd-total-mismatch | NVD の `totalResults` と返却件数が不一致 |
| nvd-only-reserved | CVE 公式は RESERVED、NVD は実質空 |
| ghsa-withdrawn | 取り下げ済みの GHSA |
| ghsa-id-mismatch | 参照 URL と応答の GHSA ID が不一致 |
| ghsa-duplicate-patch | `patched_versions` と `first_patched_version` が同値 |
