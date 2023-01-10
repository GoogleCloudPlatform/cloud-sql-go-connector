# Changelog

## [1.1.1](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v1.1.0...v1.1.1) (2023-01-10)


### Bug Fixes

* move MySQL liveness check into driver code ([#417](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/417)) ([0de68fb](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/0de68fbc32d87e4cabab301be8a11f9eba50e13d))
* use handshake context when possible ([#427](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/427)) ([37c4e70](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/37c4e70aa7082c49b84aaedb2066ddb67e1d920f))

## [1.1.0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v1.0.1...v1.1.0) (2022-12-06)


### Features

* add support for MySQL Auto IAM AuthN ([#309](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/309)) ([6c4f20e](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/6c4f20eae857c215098b7b991fffc7d15bbead5b))
* improve refresh duration calculation ([#364](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/364)) ([10b0bf7](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/10b0bf7d9d3c69238df3d0a88ffab54f03f7d7a6))


### Bug Fixes

* handle context cancellations during instance refresh ([#372](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/372)) ([cdb59c7](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/cdb59c797968f46419673378c96e79d40da453dc)), closes [#370](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/370)
* remove leading slash from metric names ([#393](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/393)) ([ac5ca26](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/ac5ca264e17adf0c5780ea2317f4df03c6e1923d))

## [1.0.1](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v1.0.0...v1.0.1) (2022-11-01)


### Bug Fixes

* update dependencies to latest versions ([#365](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/365)) ([5479502](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/547950268712f48d8613aac3d7e2a1e494b6a680))

## [1.0.0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.5.2...v1.0.0) (2022-10-18)


### Features

* add WithAutoIP option ([#346](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/346)) ([bd20b6b](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/bd20b6bfe746cfea778b9e1a9702de28047e5950))
* Downscope OAuth2 token included in ephemeral certificate ([#332](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/332)) ([d13dd6f](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/d13dd6f3e7db0179511539315dec1c2dc96f0e3e))


### Bug Fixes

* throw error when Auto IAM AuthN is unsupported ([#310](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/310)) ([652e196](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/652e196b427ce9673676e214c6ad3905b21a68b0))


### Miscellaneous Chores

* set next version to v1.0.0 ([#349](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/349)) ([a76d2db](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/a76d2db0b31447dc96707679973ff87b3c755bf5))

## [0.5.2](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.5.1...v0.5.2) (2022-09-07)


### Bug Fixes

* update dependencies to latest versions ([#300](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/300)) ([5504df6](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/5504df6e03bda7b56e01146e63b715f775443d85))

## [0.5.1](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.5.0...v0.5.1) (2022-08-01)


### Bug Fixes

* remove unnecessary import path restrictions ([#258](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/258)) ([bc57877](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/bc57877f16a61e42c603d4dc50ff4d01fc01d9d9))

## [0.5.0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.4.0...v0.5.0) (2022-07-12)


### Features

* expose the WithQuotaProject dialer option ([#237](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/237)) ([bda8917](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/bda891776d5d44d49ed3e4a268f27bd10a23427e))


### Bug Fixes

* support MySQL driver’s conn check. ([#226](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/226)) ([4b48e3b](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/4b48e3bfe7a5bd8c398592f21eb25ac43644e123))

## [0.4.0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.3.1...v0.4.0) (2022-06-07)


### Features

* add DialOption for IAM DB Authentication ([#171](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/171)) ([c103acc](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/c103acc6b49f94a1a733dc0e5c8b41890172dd8b))
* Add Warmup function for starting background refresh ([#163](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/163)) ([2459f92](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/2459f92911eeca46102f56966c8cefa7cee8a0ae))


### Bug Fixes

* adjust alignment for 32-bit arch ([#197](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/197)) ([86e96ad](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/86e96adf30cbc82ba170dc70ce4d0694a3b595ce))

### [0.3.1](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.3.0...v0.3.1) (2022-05-03)


### Bug Fixes

* update dependencies to latest versions ([#185](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/185)) ([702a380](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/702a3802d0383c0d71277779d80d62a5e5c23157))

## [0.3.0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.2.0...v0.3.0) (2022-04-04)


### Features

* add option to configure SQL Admin API URL ([#148](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/148)) ([c791369](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/c79136972083480d16f65a4696a7747bae942afe))
* add WithUserAgent opt ([#156](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/156)) ([bd89dc5](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/bd89dc50bb50d1d6ff9cf5a146071b307a54683a))
* drop support for Go 1.15 ([#145](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/145)) ([791641b](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/791641bb2d0ab93955b218b9bc6f5335b8ead243))
* use connect API for instance metadata ([#150](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/150)) ([1086ad0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/1086ad01cc7907051147d572f4f27ab1ba538027))


### Bug Fixes

* memory leak in database/sql integration ([#162](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/162)) ([47cdf2d](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/47cdf2da2230801b591bf4f459bfcbe7e9432cd1))
* prevent unnecessary allocation of conn config ([#164](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/164)) ([49c7828](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/49c782809aff84b6141027f1a2634b0a0db2b18a))

## [0.2.0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/compare/v0.1.0...v0.2.0) (2022-03-01)


### ⚠ BREAKING CHANGES

* use singular name for package (#101)

### Features

* add dial_failure_count metric ([#127](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/127)) ([34cdbb9](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/34cdbb92efa6f186bd8afdde3c8dcc810e77911e))
* add metrics for refresh success and failure ([#133](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/133)) ([a36a212](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/a36a212dbd30474721669f10fbfda1e76a22d325))
* drop support and testing for Go 1.14 ([#128](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/128)) ([aceadcc](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/aceadcc4835b6fe18639a696755302bb00f82bc2))


### Bug Fixes

* custom drivers report error on cleanup ([#102](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/102)) ([648b75a](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/648b75a4d8e43b3641d827086047a9c6783c1306))
* use singular name for package ([#101](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/101)) ([5e5589d](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/5e5589db3bb0a86d9c167cd6b85358535238176a))


## 0.1.0 (2022-02-08)


### ⚠ BREAKING CHANGES

* remove singleton Dial (#92)
* return cleanup func to close dialer (#75)
* dialer is a io.Closer (#76)
* initialize dialer in register func (#73)
* rename DialerOption to Option (#64)

### Features

* Add Close method to Dialer ([#34](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/34)) ([91ee305](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/91ee305b6af83d48ba5fc445ad1191fd99785079))
* add concrete errors to public API ([#36](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/36)) ([7441b71](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/7441b7176d8bce5d2e054aa7e53f1509aece9898))
* add custom driver for MySQL ([#70](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/70)) ([755c334](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/755c3344f28e33d18a1d7acc414352ee73e39d8a))
* add custom driver for SQL Server ([#71](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/71)) ([14eb60a](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/14eb60a88532dd81cda4d602d044c98013ee0af6))
* add default useragent ([#17](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/17)) ([57d7ed9](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/57d7ed9da73c731196bdc5120134b6dec72d9c68))
* Add DialerOption for specifying a refresh timeout ([#12](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/12)) ([94df7cf](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/94df7cfa21dc60463afb1ad3519455d507d610f3))
* add DialOptions for configuring Dial  ([#8](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/8)) ([e2d53ee](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/e2d53ee6c66ba58114d8a49ca86f0eb3a56ce481))
* Add EngineVersion method to Dialer ([#59](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/59)) ([6a78bfd](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/6a78bfd4a73807e4fce455ae0d6cd4f531710edd))
* Add initial dialer ([#1](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/1)) ([7e89552](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/7e8955216cc91999e3d8d17ed9eced8f63564ca7))
* add initial support for metrics ([#40](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/40)) ([ee396ff](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/ee396fffb10ea52af9072d0fdd09a8b4e9d4b736))
* add support for configuring the HTTP client ([#55](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/55)) ([de9e72e](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/de9e72e1dc6961f6b6ed3fe9cf4381344dd5fa37))
* add support for IAM DB Authn ([#44](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/44)) ([92e28cf](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/92e28cfccd573c0908588ad3594ef9de403e5e51))
* add support for tracing ([#32](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/32)) ([4d2acbc](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/4d2acbcecb11acbbc58f95c711051a02fb31e82f))
* allow for configuring the Dial func ([#57](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/57)) ([4cb523e](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/4cb523e80b4a388b37c8ce251a533a3b8d370029))
* expose Dialer and add DialerOptions ([#7](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/7)) ([1235a9f](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/1235a9f62beb678f18695afc6d22d0b8e6b7b506))
* force early refresh of instance info if connect fails ([#19](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/19)) ([eb06ae2](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/eb06ae26609cbc46fa65e50c080508d53ec0b9c2))
* improve reliablity of refresh operations ([#49](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/49)) ([3a52440](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/3a5244075f68f3c95f26218f9008bb7451934f80))
* improve RSA keypair generation ([#10](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/10)) ([e2a5238](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/e2a52388ff047144272089db60cb0b1fce7c16bf))
* initialize dialer in register func ([#73](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/73)) ([7633cfd](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/7633cfd2eaadeef065686f85ae9f2faa5087e917))
* **postgres/pgxv4:** add support for postgres driver ([#61](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/61)) ([295a5dc](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/295a5dcfbdaeb12884333e678f8b9f7f44de2b46))
* remove singleton Dial ([#92](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/92)) ([0a1966c](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/0a1966c4fe0400e8dcd14b2531db20ad7bc10855))
* return cleanup func to close dialer ([#75](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/75)) ([fa9b845](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/fa9b84576a7adcf8f0ad4296723685d681ada89e))
* use cloud.google.com/go/cloudsqlconn ([#30](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/30)) ([a251fd7](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/a251fd727813223dc08f40bc5060add3235564e6))


### Bug Fixes

* dialer is a io.Closer ([#76](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/76)) ([89de96c](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/89de96c2a4d636cc3dfe44aa1b47ab3492d5cf0c))
* perform refresh operations asynchronously ([#11](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/11)) ([925d6c2](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/925d6c2686d519d182dc196c752ed0c7edb0e28c))
* rate limit refresh attempts per instance ([#18](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/18)) ([1092ccc](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/1092ccc04361293f6ea07fdc97cde30cf1cb1866))
* rename DialerOption to Option ([#64](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/64)) ([016a821](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/016a821ba191b7b2117c7d240507e32c289e3f0e))
* schedule refreshes based on result expiration instead of fixed interval ([#21](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/21)) ([65073d0](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/65073d0ea9582abbe01c7ca0698681624e3c7834))
* **trace:** use LastValue for open connections ([#58](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/58)) ([4ee6bea](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/4ee6bea069c196454dd48034457a16ba416b725c))
* use ctx for NewService ([#24](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/issues/24)) ([77fd677](https://github.com/GoogleCloudPlatform/cloud-sql-go-connector/commit/77fd677ccb827feb89e6bb41eb45c22f3a2b1861))
