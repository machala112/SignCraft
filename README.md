# SignCraft — your own on-device IPA signer for iPhone

SignCraft signs IPA files **on your iPhone** with your own Apple certificate and
installs them — the same job ESign does, but it's your app, built from scratch.

How it works: import an `.ipa`, import your `.p12` certificate + `.mobileprovision`
profile once, tap **Sign app**, then **Install app**. The app re-signs every binary
inside the IPA with a real Apple CMS code signature and hands the result to iOS's
official over-the-air install flow. No computer needed after the one-time setup.

---

## Build it — no Mac needed (GitHub Actions, free)

GitHub gives you a free Mac in the cloud for public repos.

1. Create a **new public repo** on GitHub (e.g. `SignCraft`).
2. Upload everything in this folder to it (or `git push` it).
3. Open the repo → **Actions** tab → enable workflows if asked.
4. The build runs automatically. When it finishes, download **`SignCraft-ipa`**
   from the run's Artifacts section. It contains `SignCraft-unsigned.ipa`.

That's the free path — GitHub built your app, no Mac rented, nothing paid.

### Get a signed IPA straight from GitHub (needs Apple Developer account, $99/yr)

If you have a paid Apple Developer account, GitHub can also **sign** the app so
it installs directly:

1. On [developer.apple.com](https://developer.apple.com) (works from iPhone Safari):
   create a signing certificate and a provisioning profile (wildcard App ID is
   easiest), download both. Export the certificate as `.p12` (set a password).
2. In your repo: **Settings → Secrets and variables → Actions → New repository secret**:
   - `P12_BASE64` — base64 of your `.p12` file
   - `P12_PASSWORD` — the `.p12` password
   - `PROFILE_BASE64` — base64 of your `.mobileprovision` file
3. Re-run the workflow (**Actions → Build SignCraft IPA → Run workflow**).
   The artifact now also contains **`SignCraft-signed.ipa`** — installable.

Tip: to base64 a file on iPhone, use the Shortcuts app ("Encode with Base64").

## Install it on your iPhone (one time)

- **You have the signed IPA** (paid account path): upload it to
  [Diawi](https://www.diawi.com) (or any OTA install service) from your iPhone,
  open the install link in Safari, confirm. No computer at all.
- **You only have the unsigned IPA**: install it with **Sideloadly** (free) —
  needs a computer + USB cable + your Apple ID, one time, ~5 minutes.
  Free Apple ID = re-do this every 7 days (Apple's rule — same for ESign).
- **TrollStore**: if your iOS version supports it, install any IPA through
  TrollStore — permanent, no re-signing.

## Use it

1. Get your `.p12` + `.mobileprovision` onto the phone (AirDrop, Files, email…).
2. Open SignCraft → **Certificates** tab → import both.
3. **Apps** tab → **+** → import any `.ipa`.
4. Tap the app → choose certificate + profile → **Sign app** → **Install app**.
5. Confirm the iOS install prompt. Done.

## What you need, honestly

- GitHub builds the app free — that part is solved.
- But **installing** any iPhone app requires it to be signed with a certificate
  tied to **your** Apple ID. Nobody can generate that for your phone — it's
  Apple's security model, and ESign works the same way (that's why it asks for
  your own `.p12`).
- So you need **either** a paid Apple Developer account ($99/yr → fully
  phone-only: GitHub signs it, you install from a link) **or** a computer with
  Sideloadly + your free Apple ID for the one-time install.

## Notes & limits (v1)

- Re-signs the main executable, frameworks, app extensions and dylibs (fat +
  thin binaries). Sealed resources are never touched, so the original
  `_CodeSignature/CodeResources` stays valid.
- No tweak/dylib injection yet.
- The app's bundle ID must be covered by your provisioning profile (wildcard
  profiles cover everything).
- Binaries must already contain an `LC_CODE_SIGNATURE` slot (true of every
  normally-built IPA).

## Alternative: build on a Mac

If you have a Mac (or rent one — [MacinCloud](https://www.macincloud.com/pages/payg.html)
pay-as-you-go is $1/hour, Xcode pre-installed): open `SignCraft.xcodeproj` in
Xcode, set your own bundle identifier, and run `./build.sh` → `SignCraft-unsigned.ipa`.

## Project layout

```
SignCraft/
  .github/workflows/ – GitHub Actions build (+ optional signing)
  App/        – entry point, root view, central AppStore state
  Models/     – IPAFile, SigningIdentity (.p12), ProvisioningProfile
  Signing/    – DER writer, X.509 parser, CMS encoder, Mach-O parser,
                CodeDirectory/SuperBlob builder, IPA re-sign orchestrator
  Install/    – local HTTP server + itms-services OTA install flow
  UI/         – Apps list, Certificates, Sign & Install flow
```

Built with Swift 5, SwiftUI, CryptoKit, Security, Network — plus
[ZIPFoundation](https://github.com/weichsel/ZIPFoundation) (SPM).
