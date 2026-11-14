# Security audit: Pinky (DIYgod/pinky, this fork)

**Verdict: Caution**

This review found no hidden command-and-control channel, backdoor, credential-stealing payload, or obfuscated malware in the source tree or in the release assets that were opened. Pinky is intentionally a high-privilege phone automation tool: the default safety preset asks only before payments, anonymous usage statistics are on by default, and the iPhone kit’s prebuilt core is downloaded without a SHA-256 check. A free Apple ID and 全能签 cannot turn the published archive into a working full app; the release has no IPA, and the packet-tunnel build needs a paid developer account.

**结论：Caution（谨慎使用）。** 这次检查没有发现隐藏远控、后门、窃取凭据的载荷，或经过混淆的恶意代码。Pinky 本身就是高权限的手机自动化工具：默认只在付款前询问，匿名使用统计默认开启，iPhone 安装套件里的预编译核心库下载时不校验 SHA-256。免费 Apple ID 配合全能签不能把发布包直接变成可用的完整版应用：发布物里没有 IPA，带数据包隧道的完整版需要付费开发者账号。

Audit date: 2026-11-14. Tree: `Lin00700/pinky` `main` at `30efc9f0eaf60e85b65ced0e232dd058ccb13bb1`. That commit is the target of upstream annotated tag `v2026.1114.2` (`0a41cebabf0e398df59b1e2f61189c1d92d5ad2b`, unsigned). No extra commits sit on top of that tag in this checkout. License of the upstream project: Apache-2.0.

This is a source and release-asset review, not a dynamic malware sandbox run and not a full disassembly. “No backdoor found” means the searches and spot checks below did not turn one up. It is not a claim that every byte of every desktop binary was proven clean.

## What was checked

- Source on this commit: Go desktop app and gateway (`cmd/pinky`, `internal/gateway`, `internal/mcp`, `internal/policy`, `internal/approval`, `internal/update`, `internal/telemetry`, `internal/pilot`), Android companion (`android/companion`), iPhone app and core (`ios/`), WebDriverAgent install path (`internal/driver/ios`), telemetry worker (`worker/`).
- Searches for URLs and IPs, `os/exec`, base64, private keys, API tokens, wallet mnemonics, reverse shells, `eval`, clipboard theft, and keylogging beyond the accessibility tree the product documents.
- Update, telemetry, approval, credential, and iPhone-install code paths, read rather than only grepped.
- Upstream release `v2026.1114.2` at <https://github.com/DIYgod/pinky/releases/tag/v2026.1114.2>. This fork had no need of its own assets: `main` is the tagged commit. Hashes below were computed locally with `sha256sum` and matched GitHub’s asset `digest` and `SHA256SUMS`.
- Opened and inspected: `latest.json`, `SHA256SUMS`, `pinky-iphone-2026.1114.2.tar.gz` (full file list, entitlements, pairing file, strings in `libpinkycore.a`, Swift sources compared with this tree), `pinky-android.apk` (layout, `classes.dex` strings, `libpinkycore.so` strings, APK Signature Scheme v2 certificate), `pinky-2026.1114.2-linux-amd64.tar.gz` (ELF `pinky`: `go version -m` and URL strings).
- Not downloaded, so not inspected inside: macOS `.zip` / `.dmg`, Windows `.zip` / `pinky-setup-*.exe`, `.deb`, `.mcpb`, `pinky.rb`. Their GitHub digests match `SHA256SUMS`. Do not treat those binaries as reviewed.

## Findings

### Medium — iPhone kit is a prebuilt binary fetched without a checksum

`internal/driver/ios/appinstall.go` downloads `https://github.com/DIYgod/pinky/releases/download/v<version>/pinky-iphone-<version>.tar.gz` and unpacks it. The download checks HTTP 200 and a 256 MiB cap. It does not check `SHA256SUMS` or `latest.json`. Desktop auto-update does check SHA-256, and on macOS also requires Developer ID team `492J8Q67PF` plus Apple notarization (`internal/update`).

The archive’s bulk is `pinky-iphone/build/core/libpinkycore.a` (34,118,824 bytes), a Mach-O static library linked into the app the person then signs with their own Apple ID. Swift sources in the archive match this tree aside from `MARKETING_VERSION` (`0.1` in git, `2026.1114.2` in the kit). The library was not rebuilt here, so byte-identity with this source was not proven. String extraction found the model APIs, Apple’s TSS URL, and the pinned DeveloperDiskImage mirror. It did not contain `pinky-telemetry`, an anisette host, a shell, or an unexpected domain that survived as a real URL. `build/Pairing.json` is `{}`.

Anyone who can replace that GitHub asset can put code into an app the user signs. Prefer building `ios/build.sh` from this source on a Mac you trust, or check the archive against the hash in the table below before `pinkyctl helper install` uses it.

### Low — usage statistics and crash reports are on by default

`telemetry.Endpoint` is `https://pinky-telemetry.rss3.workers.dev`. `usageStatsByDefault` is true (`ui/telemetry.go`). The first run does not announce this. Settings › Privacy (「设置 › 隐私」) turns both off and drops unsent counts. `DO_NOT_TRACK` set to anything other than empty, `0`, `false`, `no`, or `off` stops both regardless of the switch (`internal/telemetry/telemetry.go` `DoNotTrack`). `PINKY_TELEMETRY_URL=-` sends nothing. Development builds (`0.0.0-dev`) do not use the built-in endpoint unless that variable names a backend.

What is posted, when the switch is on, matches `docs/TELEMETRY.md` and `worker/src/validate.js`: a random `install_id`, version, OS, architecture, and fixed-name counters (`/v1/usage`, about once a day), plus crash reason and Go stack (`/v1/crash`, no install id). The worker refuses unknown shapes. It does not store the request’s IP in D1; Cloudflare still sees the connection address for a one-minute rate limit. A redactor strips home directory, user name, e-mail, IP addresses, and long hex strings from crash text before send. Redaction is best-effort, not a proof that a stack can never contain a path or a secret.

The Android and iPhone on-phone cores do not reference this host. `classes.dex` and `libpinkycore.so` in the APK, and `libpinkycore.a` in the iPhone kit, have no `workers.dev` string. The phone apps talk to the model the person configures and, on Android, to GitHub for updates.

Feedback is a GitHub issue the person submits themselves. Diagnostics can include redacted logs and phone model/OS. Nothing is posted until they submit it.

### Low — optional third-party developer disk image

If the person asks, and only then, Pinky downloads Xcode 27.0 beta 4’s developer disk image from `https://raw.githubusercontent.com/doronz88/DeveloperDiskImage/e2aaeac89ca8fa56c2fa1f144d182994e07a525b/PersonalizedImages/` (`internal/driver/ios/mirror.go`). Each file is pinned by size and SHA-256. A mismatch is refused. The phone still mounts only an image Apple’s signing server personalizes (`https://gs.apple.com/TSS/controller?action=2`). Pinky does not ship Apple’s disk image. There is no anisette helper, AltServer, or Sideloadly-style signing service in this tree.

### Info — high privilege is the product, and the default preset is wide

An agent that the person has approved can read the accessibility tree and type, tap, and swipe. Secure password and one-time-code fields are refused on real phones (`internal/policy/engine.go`). Settings › Safety › Allow passwords on virtual phones (「设置 › 安全 › 允许在虚拟手机上输入密码」, `virtual_credentials`, off by default) lifts that only when `driver.Info.Virtual` is set. A phone whose serial looks like an emulator is still treated as a phone.

Other hard refusals that an agent cannot click through: Pinky’s own screens (so it cannot tap Allow or Stop), password managers, finance apps for install/uninstall/stop, system apps, and apps the person blocked. Banking and wallet apps are hidden from the agent’s screen by the bundled `apps.yaml` list. Installing or uninstalling an ordinary app always asks.

The default preset is payments only (`PresetPayments`). Messages, commits, calls, settings changes, links, and ordinary taps do not ask unless the person picks a stricter preset or adds a rule. “Always allow” stores a rule the person chose. The first connection of a new agent is a separate approval. Remote MCP listens on `127.0.0.1:7465` unless the person sets another address; a non-loopback address is labeled as reachable by other computers and still requires the bearer token (`internal/mcp/http.go`). The companion’s abstract socket `@pinky_companion` accepts only the shell user (adb), root, and its own uid.

Screen contents and typed text go to the model provider the person configured (Anthropic, OpenAI, or a base URL they type). That is not sent to Pinky’s telemetry host. It is still data leaving the computer.

The packet tunnel (`ios/app/Tunnel/PacketTunnelProvider.swift`, entitlement `com.apple.developer.networking.networkextension` = `packet-tunnel-provider` only) routes `10.7.0.1/32`, swaps IPv4 source and destination, and excludes the default route. It is a loopback so `remotepairingd` on the same phone answers. It is not a device-wide VPN and it does not forward traffic to a Pinky server. The lite build has no tunnel of its own and expects LocalDevVPN from the App Store to do that reflection.

### Info — release hygiene, not a backdoor

The Linux `pinky` binary’s build info is `github.com/DIYgod/pinky v0.0.0-20261114015154-30efc9f0eaf6+dirty`, path `github.com/DIYgod/pinky/cmd/pinky`, Go 1.27.3. The commit matches the tag. `+dirty` means the release builder had uncommitted files. What those files were was not recovered from the binary. URL strings in that binary match the source (model APIs, GitHub, telemetry, Apple TSS, the pinned mirror, agent download pages, a `#!/bin/sh` helper that execs the installed Pinky as an MCP server for Claude Desktop). `https://check-proxy-existence.com` is a dummy URL in `modelcontextprotocol/go-sdk` `oauthex/oauth2.go`: the SDK asks the local proxy function whether a proxy would be used, and does not dial that host.

`pinky-android.apk` is APK Signature Scheme v2, one self-signed certificate: subject `O = Pinky, CN = Pinky Companion`, valid 2026-11-08 to 2056-11-08, SHA-256 `7A:0F:AA:EF:34:62:6E:B2:9B:88:99:55:8E:A2:FE:49:13:40:12:59:1F:43:8D:6C:B9:4B:6B:9F:16:D6:19:EF`. That is the fingerprint `docs/RELEASING.md` records for the release key. The private keystore is not in the tree. The old debug keystore that was briefly committed is gone. Android will not install a different signer over this package.

No `.env`, `.pem` private key, `.p12`, or cloud token showed up in the tree. `internal/driver/ios/apple-root-ca.pem` is Apple’s public root. `go.mod` replaces `github.com/danielpaulus/go-ios` with `github.com/DIYgod/go-ios` at `53a1fc8154fc`. `gvisor` is the userspace TCP stack for the CoreDevice tunnel, not a second network path off the machine.

## Network and telemetry map

| Destination | Who calls it | When |
| --- | --- | --- |
| `https://github.com/DIYgod/pinky/releases/latest/download/latest.json` | Desktop updater; Android `UpdateCheck` | Update check. Override: `PINKY_UPDATE_FEED` (HTTPS, or HTTP to loopback only). |
| `https://github.com/DIYgod/pinky/releases/download/v…/` | Desktop updater (sha256 + size; macOS also codesign/notarization); Android APK install (sha256 + size, URL must stay on `github.com` / `objects.githubusercontent.com` / `release-assets.githubusercontent.com`); iPhone kit download (no hash) | Person installs an update, or desktop Pinky installs the iPhone kit. |
| `https://pinky-telemetry.rss3.workers.dev/v1/usage` and `/v1/crash` | Desktop app and `pinky daemon` only | While Settings › Privacy is on and `DO_NOT_TRACK` is unset. Not used by the phone apps. |
| `https://github.com/DIYgod/pinky/issues/new` | Desktop “Send feedback” | Person opens the browser and submits. |
| Model APIs in `internal/pilot/services.go` (Anthropic, OpenAI, DeepSeek, Gemini, Kimi, Qwen, SiliconFlow, Ark, Zhipu, OpenRouter, Ollama, LM Studio, or a custom base URL) | Desktop and on-phone agent loop | Only after the person saves a key and starts a task. Prompts can include the screen. |
| `https://gs.apple.com/TSS/controller?action=2` | iOS driver | Personalizing a developer disk image. |
| `raw.githubusercontent.com/doronz88/DeveloperDiskImage/<pinned commit>/…` | iOS driver | Only after the person asks for the mirror. |
| `https://tailscale.com/download` | Settings UI link | Person clicks it. Tailscale itself is optional, for remote agents and away-from-home Android. |
| `10.7.0.1` on the iPhone | Pinky tunnel or LocalDevVPN | Loopback to `remotepairingd` on that phone. Not an external host. |
| Phone on USB, Wi-Fi (`adb`), or a Tailscale `100.64.0.0/10` address | Desktop drivers | The person’s devices. Companion socket is not on the network; adb forwards it. |
| MCP `127.0.0.1:7465` by default | Local agents | Bearer token. Binding `0.0.0.0` is a setting the UI warns about. |

No hard-coded public IPv4 command server, paste site, ngrok host, Discord webhook, or Telegram bot URL appeared in the source or in the binaries that were opened. Messaging package names (`org.telegram.messenger`, `com.discord`) are entries in the app block list.

## Secrets scan

Searched the tree for private-key blocks, `AKIA` access-key ids, `ghp_` / `xox` / `sk-` tokens, and files named `.env`, `.pem` (other than Apple’s public root), `.p12`, `.jks`, `.keystore`. None of those secrets are present. The Android release key is documented as living in GitHub Actions secrets and the maintainer’s password manager, not in git. The APK certificate matches that documented public fingerprint. The iPhone kit contains no pairing identity.

## Release assets (`v2026.1114.2`)

Local `sha256sum` of files actually downloaded:

| Asset | SHA-256 | What was done with it |
| --- | --- | --- |
| `latest.json` | `c8c153d27c35d44e7fe424e28a578d391f0b0ba8bcc4d69bd5e7ab094af56044` | Read. Feed points only at `github.com/DIYgod/pinky` release URLs. Notes are the GPT-6 / Responses API changes. |
| `SHA256SUMS` | `df6886394501c45e4fa328bab47c80fe9eb62e8e3e708344948d94f48b87b48a` | Read. Every line matches GitHub’s asset digest, including files not downloaded. |
| `pinky-iphone-2026.1114.2.tar.gz` | `28a55b85e0adb54d532d5f63558535cf1d57d023f70c8cbe81717d3769bb4bee` | Unpacked. See below. |
| `pinky-android.apk` | `afcdf21ede4cf827eb1559172d289cb529ff191ce763d2ccbce2d9a411d5432b` | Unpacked, strings, v2 certificate. 25,703,163 bytes. `version_code` 1328 in `latest.json`. |
| `pinky-2026.1114.2-linux-amd64.tar.gz` | `9718181698cd7c6b2d8df6fdb30c1a972e3fb5c8cf34de95dbe76eb0ebba297f` | Unpacked. Inner ELF `pinky` SHA-256 `62616a6cea48afd0aeb7243bfea152a9ed6d11d22482066afbb0bde7603ec887`. String and build-info review only. Not executed. |

`SHA256SUMS` also lists, and GitHub’s digest matches, these files that were **not** opened: `pinky-2026.1114.2-amd64.dmg` `c09a570b…`, `pinky-2026.1114.2-arm64.dmg` `3a2b84ac…`, `pinky-2026.1114.2-darwin-amd64.zip` `36366200…`, `pinky-2026.1114.2-darwin-arm64.zip` `5b804b47…`, `pinky-2026.1114.2-windows-amd64.zip` `021e4ab5…`, `pinky-setup-2026.1114.2-amd64.exe` `5a2453c8…`, `pinky_2026.1114.2_amd64.deb` `df47cf3d…`, `pinky-2026.1114.2.mcpb` `d0ce7db3…`, `pinky.rb` `85b964c3…`.

### What is inside `pinky-iphone-2026.1114.2.tar.gz`

66 entries under `pinky-iphone/`. It is **not** a signed `.app` and **not** an IPA.

- XcodeGen project (`project.yml`, `Pinky.xcodeproj`) and Swift sources for the app, the packet-tunnel extension, and the Live Activity.
- Generated plists and entitlements. The only entitlement is `packet-tunnel-provider` on the app and on `PinkyTunnel`.
- `build/core/libpinkycore.a` and `libpinkycore.h`: the Go core already compiled for `iphoneos` arm64 (`ar` archive, 15 members). This is the prebuilt binary.
- `build/Pairing.json`: `{}`.
- No `WebDriverAgentRunner.xctest`, no provisioning profile, no signature.

Desktop Pinky, on a Mac with Xcode, builds scheme `Pinky` (bundle id `pinky.<team id>`) or, when the team cannot sign Network Extensions, `PinkyLite` (`pinky.<team id>.lite`). It then copies a WebDriverAgent runner built on that Mac into `PlugIns`, re-signs with the person’s certificate, and installs with `xcodebuild test-without-building`. A free personal team fails the full scheme and falls back to lite. That path is documented in `docs/notes/iphone-app.md`.

## Practical advice: 全能签 and a free Apple ID

The published tar.gz cannot be installed by 全能签, Sideloadly, AltStore, or SideStore. Those tools re-sign an IPA or an `.app`. This archive still has to be compiled. Swift sources plus `libpinkycore.a` need Xcode and the iPhoneOS SDK on a Mac. There is no supported way to produce the IPA on Linux or Windows from this release.

If you have a Mac:

1. Check the tar against `28a55b85e0adb54d532d5f63558535cf1d57d023f70c8cbe81717d3769bb4bee` before use, because Pinky’s installer will not.
2. Build **PinkyLite**, not Pinky. A free Apple ID’s profile cannot contain the Network Extensions capability. 全能签 keeps only entitlements the profile has, so a full build’s packet tunnel is stripped or refused and the core never reaches `remotepairingd`.
3. Export an IPA from that `.app` (`Payload/Pinky.app` in a zip named `.ipa`) and sign it in 全能签 with your Apple ID. Keep one bundle id. A free account allows a handful of App IDs and about three apps on the phone, and the profile stops launching the app after 7 days. Re-sign before it expires. The app reads `embedded.mobileprovision` and can warn about two days ahead.
4. Install **LocalDevVPN** from the App Store and set a `/30`: phone `10.7.0.2`, peer `10.7.0.1`. The lite build has no tunnel of its own. LocalDevVPN’s default `10.7.1.1/32` does not work with this app.
5. Turn on Developer Mode. On iOS 27 the app can pair on the phone (Settings › Privacy & Security › Developer Mode). On iOS 17.4–26 you still need a Mac once to create a RemotePairing file. The developer disk image has to be mounted (Xcode, desktop Pinky, or the pinned mirror). The on-phone app does not mount it yet.
6. Allow Local Network. The VPN prompt appears only for the full build. Allow Face ID / passcode for approvals. Put the model key in the app’s Settings; it is stored in the Keychain on the device (`AfterFirstUnlockThisDeviceOnly`).
7. Do not install an IPA you did not build. The interesting code is `libpinkycore.a`. Signing it with your Apple ID makes iOS trust whatever was in that library.

On the computer, if you use desktop Pinky: set `DO_NOT_TRACK=1` or turn off Settings › Privacy if you do not want counts and crash stacks sent to `pinky-telemetry.rss3.workers.dev`. Leave “Allow passwords on virtual phones” off unless you are testing on an emulator. Prefer the payments-or-stricter preset if an agent should not send messages or change settings on its own. Keep remote agents on `127.0.0.1` unless you mean them to be reachable.

The Android APK from this release can be sideloaded as-is. Its signer is the certificate above. A rebuild you sign yourself will not update that install in place; uninstall first, and only if you intend to replace it. The accessibility service can read other apps’ windows and perform gestures. Android shows that consent dialog; read it. The service is how both desktop mode and on-phone tasks see the screen.
