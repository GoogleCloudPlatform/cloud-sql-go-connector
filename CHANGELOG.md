# Changelog

## 1.0.0 (2022-02-07)


### ⚠ BREAKING CHANGES

* initialize dialer in register func (#73)
* rename DialerOption to Option (#64)

### Features

* Add Close method to Dialer ([#34](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/34)) ([91ee305](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/91ee305b6af83d48ba5fc445ad1191fd99785079))
* add concrete errors to public API ([#36](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/36)) ([7441b71](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/7441b7176d8bce5d2e054aa7e53f1509aece9898))
* add default useragent ([#17](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/17)) ([57d7ed9](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/57d7ed9da73c731196bdc5120134b6dec72d9c68))
* Add DialerOption for specifying a refresh timeout ([#12](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/12)) ([94df7cf](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/94df7cfa21dc60463afb1ad3519455d507d610f3))
* add DialOptions for configuring Dial  ([#8](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/8)) ([e2d53ee](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/e2d53ee6c66ba58114d8a49ca86f0eb3a56ce481))
* Add EngineVersion method to Dialer ([#59](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/59)) ([6a78bfd](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/6a78bfd4a73807e4fce455ae0d6cd4f531710edd))
* Add initial dialer ([#1](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/1)) ([7e89552](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/7e8955216cc91999e3d8d17ed9eced8f63564ca7))
* add initial support for metrics ([#40](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/40)) ([ee396ff](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/ee396fffb10ea52af9072d0fdd09a8b4e9d4b736))
* add support for configuring the HTTP client ([#55](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/55)) ([de9e72e](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/de9e72e1dc6961f6b6ed3fe9cf4381344dd5fa37))
* add support for IAM DB Authn ([#44](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/44)) ([92e28cf](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/92e28cfccd573c0908588ad3594ef9de403e5e51))
* add support for tracing ([#32](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/32)) ([4d2acbc](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/4d2acbcecb11acbbc58f95c711051a02fb31e82f))
* allow for configuring the Dial func ([#57](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/57)) ([4cb523e](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/4cb523e80b4a388b37c8ce251a533a3b8d370029))
* expose Dialer and add DialerOptions ([#7](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/7)) ([1235a9f](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/1235a9f62beb678f18695afc6d22d0b8e6b7b506))
* force early refresh of instance info if connect fails ([#19](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/19)) ([eb06ae2](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/eb06ae26609cbc46fa65e50c080508d53ec0b9c2))
* improve reliablity of refresh operations ([#49](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/49)) ([3a52440](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/3a5244075f68f3c95f26218f9008bb7451934f80))
* improve RSA keypair generation ([#10](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/10)) ([e2a5238](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/e2a52388ff047144272089db60cb0b1fce7c16bf))
* initialize dialer in register func ([#73](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/73)) ([7633cfd](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/7633cfd2eaadeef065686f85ae9f2faa5087e917))
* **postgres/pgxv4:** add support for postgres driver ([#61](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/61)) ([295a5dc](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/295a5dcfbdaeb12884333e678f8b9f7f44de2b46))
* use cloud.google.com/go/cloudsqlconn ([#30](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/30)) ([a251fd7](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/a251fd727813223dc08f40bc5060add3235564e6))


### Bug Fixes

* perform refresh operations asynchronously ([#11](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/11)) ([925d6c2](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/925d6c2686d519d182dc196c752ed0c7edb0e28c))
* rate limit refresh attempts per instance ([#18](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/18)) ([1092ccc](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/1092ccc04361293f6ea07fdc97cde30cf1cb1866))
* rename DialerOption to Option ([#64](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/64)) ([016a821](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/016a821ba191b7b2117c7d240507e32c289e3f0e))
* schedule refreshes based on result expiration instead of fixed interval ([#21](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/21)) ([65073d0](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/65073d0ea9582abbe01c7ca0698681624e3c7834))
* **trace:** use LastValue for open connections ([#58](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/58)) ([4ee6bea](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/4ee6bea069c196454dd48034457a16ba416b725c))
* use ctx for NewService ([#24](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/24)) ([77fd677](https://www.github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/77fd677ccb827feb89e6bb41eb45c22f3a2b1861))
