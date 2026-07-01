# Changelog

## [1.3.4](https://github.com/dmakeienko/adel/compare/v1.3.3...v1.3.4) (2026-07-01)


### Bug Fixes

* maintanance release - fix goreleaser to build ui assets ([a5e4b0e](https://github.com/dmakeienko/adel/commit/a5e4b0ef83403a9a70fb70458cc7e58ae24d373e))

## [1.3.3](https://github.com/dmakeienko/adel/compare/v1.3.2...v1.3.3) (2026-07-01)


### Bug Fixes

* maintanance release - decouple docker from goreleaser ([2d3d165](https://github.com/dmakeienko/adel/commit/2d3d165fc7e57ae79ab18804192f4bb9b92d1e73))

## [1.3.2](https://github.com/dmakeienko/adel/compare/v1.3.1...v1.3.2) (2026-07-01)


### Bug Fixes

* maintenance fix to resolve release issue and add dependency on helm publish ([728c16c](https://github.com/dmakeienko/adel/commit/728c16cfa6712b08127c0483af759c0090bc18b7))


### Chores

* bump helm chart to 1.3.1 ([a85b73a](https://github.com/dmakeienko/adel/commit/a85b73ab58b39a2d48fead6f85155e93aaa1a1c5))

## [1.3.1](https://github.com/dmakeienko/adel/compare/v1.3.0...v1.3.1) (2026-07-01)


### Bug Fixes

* maintenance fix to resolve release issue ([9987ca5](https://github.com/dmakeienko/adel/commit/9987ca52e020de5a805fd3bb5a2808751dfa6327))


### Chores

* bump helm chart to 1.3.0 ([7a408d4](https://github.com/dmakeienko/adel/commit/7a408d4c034a63695b149f963d9ede1a9b96e3bf))

## [1.3.0](https://github.com/dmakeienko/adel/compare/v1.2.2...v1.3.0) (2026-07-01)


### Features

* add filters for search, exclusion for groups and other objects ([7cb7f27](https://github.com/dmakeienko/adel/commit/7cb7f27bfc605e6d7bec0d63545dce45f78d92c7))
* add filters for search, exclusion for groups and other objects ([a0198b8](https://github.com/dmakeienko/adel/commit/a0198b8f9495a772a4e93492df6cca30d27d3c4c))
* integrate UI into repo ([1de76b5](https://github.com/dmakeienko/adel/commit/1de76b59d3d896fa5882984e44af55e74e5fe296))


### CI/CD

* add build-ui step to prevent lint from failing ([f382450](https://github.com/dmakeienko/adel/commit/f38245068828f009a6b53d17f35b1d728b4c0310))
* add concurrency group ([a101e75](https://github.com/dmakeienko/adel/commit/a101e7527ad9f7882ea2d063e44d0024d15b3804))
* add dependabot config ([9f24eae](https://github.com/dmakeienko/adel/commit/9f24eaea3025e48c39adad566d93eb821871c3c7))
* add helm chart and release for it ([86bc096](https://github.com/dmakeienko/adel/commit/86bc096e1c4e9eb1b0be019fa0eb877552483636))
* add helm chart checks ([20133f0](https://github.com/dmakeienko/adel/commit/20133f03a83fe9a23af9d227dd9138f358a2c0a7))
* add missing dockerignore ([80de9ea](https://github.com/dmakeienko/adel/commit/80de9ea9d33b22742c346226d09095b9e0a0f04f))
* **build:** update Dockerfile to use distroless image ([8892780](https://github.com/dmakeienko/adel/commit/8892780fe1c62b9edbdd5a1e796cc11a35fc65c4))
* change sonarcloud scan ([385011a](https://github.com/dmakeienko/adel/commit/385011a14bafe06a4440ad353ed6aca80acda433))
* fix dependabot file ([0296382](https://github.com/dmakeienko/adel/commit/029638274120215e687610cf00d74a65fb2cc48c))
* fix dependabot sonar scan ([3d3920c](https://github.com/dmakeienko/adel/commit/3d3920c57140792064e76397bfa56a5c45dd2da0))
* fix missing release-please-manifest ([272cb40](https://github.com/dmakeienko/adel/commit/272cb401ce98abd11b64651261399ccc3efbcb95))
* fix test by adding ui build step ([d5f0954](https://github.com/dmakeienko/adel/commit/d5f0954ca78eadb047cf6306da3ad91164f60c9b))
* merge codeql into ci ([a77de95](https://github.com/dmakeienko/adel/commit/a77de956553ca0a565721bafdaec85fff7507f67))
* recombine ci jobs ([2a6747b](https://github.com/dmakeienko/adel/commit/2a6747bd8f0b3f4d2439c1b3207a4385500e2f68))
* simplify workflows; use goreleaserer; add vulncheck ([a7b2145](https://github.com/dmakeienko/adel/commit/a7b21455fd4194354a2895482045e9dce728c888))


### Chores

* upgrade go to 1.26.4 ([135843c](https://github.com/dmakeienko/adel/commit/135843cd8362256c26ab01ee2cd9cd1127d36017))


### Code Refactoring

* clarify error message during change password ([be70591](https://github.com/dmakeienko/adel/commit/be705918e43aac7649bfe4a76ab3886fe681a66a))


### Dependencies

* **deps:** bump esbuild and vite in /web ([2025c86](https://github.com/dmakeienko/adel/commit/2025c862108f696f502b337e31f453df356adbef))
* **deps:** bump esbuild and vite in /web ([30f8b48](https://github.com/dmakeienko/adel/commit/30f8b48b672ad766e189b8dc879cde19dffbc8f9))
* **deps:** bump github.com/go-ldap/ldap/v3 ([75e0f66](https://github.com/dmakeienko/adel/commit/75e0f66f63212c6b81ac7644dc364a868b779586))
* **deps:** bump github.com/go-ldap/ldap/v3 from 3.4.6 to 3.4.13 in the go-dependencies group across 1 directory ([2aaea86](https://github.com/dmakeienko/adel/commit/2aaea866343b7123383d4028e089445841c99b3a))
* **deps:** bump the github-actions group across 1 directory with 10 updates ([6f681a2](https://github.com/dmakeienko/adel/commit/6f681a2a6b184b4c4770a85392d58cdf6893aaf9))
* **deps:** bump the github-actions group across 1 directory with 10 updates ([ecb05eb](https://github.com/dmakeienko/adel/commit/ecb05eb188a49343fe3b76333b25b0fec419b73a))
* **deps:** bump the npm_and_yarn group across 1 directory with 9 updates ([c5934c2](https://github.com/dmakeienko/adel/commit/c5934c299464bca8e414e2a84ab6a79d4d8b0b8e))
* **deps:** bump the npm_and_yarn group across 1 directory with 9 updates ([5c254ac](https://github.com/dmakeienko/adel/commit/5c254ac63c7fbcdda1843a0328e72b45fcb627ed))
* **deps:** bump ui deps ([494157e](https://github.com/dmakeienko/adel/commit/494157e8432102745d51c462c32c96f493997aaf))

## [1.2.2](https://github.com/dmakeienko/adel/compare/v1.2.1...v1.2.2) (2026-03-02)


### Bug Fixes

* G115 (integer overflow rune -&gt; byte); update nolintlint ([c5404f3](https://github.com/dmakeienko/adel/commit/c5404f364d0c217a1850fb881c512bc16ea0c652))

## [1.2.1](https://github.com/dmakeienko/adel/compare/v1.2.0...v1.2.1) (2026-02-09)


### Bug Fixes

* maintanence release to fix binaries upload ([3cfd662](https://github.com/dmakeienko/adel/commit/3cfd662328662f7209ea8a5419f973e602e0a233))

## [1.2.0](https://github.com/dmakeienko/adel/compare/v1.1.0...v1.2.0) (2026-02-08)


### Features

* add ability to change user password ([178fd06](https://github.com/dmakeienko/adel/commit/178fd062094a6341307d90f0db5523c955cbccf7))
* add ability to change user password ([8c7c272](https://github.com/dmakeienko/adel/commit/8c7c272f533de28286bb89e58fab65ac8329e4d4))


### Bug Fixes

* G115: integer overflow conversion uint64 -&gt; int64 (gosec) ([8883bee](https://github.com/dmakeienko/adel/commit/8883bee728241753a326d8c711a37ae445097c7c))

## [1.1.0](https://github.com/dmakeienko/adel/compare/v1.0.0...v1.1.0) (2025-12-07)


### Features

* add "msDS-UserPasswordExpiryTimeComputed" ([b32d83e](https://github.com/dmakeienko/adel/commit/b32d83e296b2e8da157160009f37950cafb850f4))
* return "accountExpires" attribute in correct format ([c1b82a6](https://github.com/dmakeienko/adel/commit/c1b82a6a098b568aae3946b737b92ae2a0bd4e1c))
* return pwdLastSet in correct format ([71ac1e0](https://github.com/dmakeienko/adel/commit/71ac1e09af18204f8c06cf6d5e6121108122478f))
* return pwdLastSet in correct format ([cee75ac](https://github.com/dmakeienko/adel/commit/cee75ac27444ec221d9811ad58bba5c4a7fc21eb))


### Bug Fixes

* return null for account expiration fields ([0f09298](https://github.com/dmakeienko/adel/commit/0f09298297e7cdd1966ff1f61c1c29381a978c03))

## 1.0.0 (2025-12-05)


### ⚠ BREAKING CHANGES

* core functionality

### Features

* core functionality ([f906c3d](https://github.com/dmakeienko/adel/commit/f906c3d7bda947c644754c84560097d70a6dcd9a))


### Bug Fixes

* errcheck findings ([95cd9a8](https://github.com/dmakeienko/adel/commit/95cd9a813a426352b059146ff2b61d2794f37f49))
* exitAfterDefer ([9ba4417](https://github.com/dmakeienko/adel/commit/9ba441780592edeeb97028e19cb0318d096c91e0))
* InsecureSkipVerify remove hardcoded true ([f5c1d7b](https://github.com/dmakeienko/adel/commit/f5c1d7b42d727284142898c27312f768bd935257))
