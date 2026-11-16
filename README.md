# VaultSpace

Secure storage and controlled sharing of sensitive documents. This is the Group 15 project for Usable Security & Privacy, Monsoon 2026.

- **Encrypted on the phone.** Files and their names are encrypted before upload; the server stores only ciphertext.
- **End-to-end sharing.** The owner sets expiry, an open limit, the permission (view only / view & download / can update) and an optional passphrase, and can revoke at any time. The server enforces every rule on every request.
- **Original code, no libraries.** About 4,900 lines of original code. The server uses only Node.js built-ins; the app uses only the Android framework (`dependencies { }` is empty).

```
vaultspace/
  server/              Node.js server (no npm dependencies)
    src/               app code (see docs/VIVA_GUIDE.md §7 for a file-by-file tour)
    test/              22 tests (access control, races, limits, enumeration, mail client...)
    scripts/make-cert.sh   TLS key + self-signed certificate that the app pins
    deploy/            VM setup script, hardened systemd unit, config template
  android/             Android app (Kotlin, Android framework only)
  docs/
    VIVA_GUIDE.md      how everything works and why: start here
    SECURITY.md        security requirements, threat model, controls, tests
    USER_GUIDE.md      for testers
```

## Run the server locally
Needs Node.js 22.13 or newer.
```bash
cd server
bash scripts/make-cert.sh          # creates data/tls/{key,cert}.pem
npm start                          # https://0.0.0.0:8443, prints email codes to the console
npm test                           # runs the security test suite
```

## Build the app
Needs the Android SDK (API 35) and JDK 17+.
- **Release** builds talk only to `vsServer` (the course VM, `https://192.168.2.242`) and trust only
  `app/src/main/res/raw/server_cert.pem`, the VM's certificate.
- **Debug** builds talk to `vsDevServer` (default `https://10.0.2.2:8443`, which is the laptop as seen
  from the emulator). They also trust `app/src/debug/res/raw/dev_cert.pem`, the local server's certificate.

```bash
cd android
./gradlew assembleRelease          # app/build/outputs/apk/release/app-release.apk (signed if keystore.properties exists)
./gradlew assembleDebug            # local testing; add -PvsSecure=false to allow screenshots
```

## Deploy to a VM
Copy the `server` folder to the VM, then run:
```bash
sudo bash server/deploy/setup-vm.sh <vm-ip>
```
After that:
1. Put the email settings in `/etc/vaultspace.env`.
2. Copy `/var/lib/vaultspace/tls/cert.pem` into the app.
3. Build the release APK.
4. Allow only key logins over SSH, once your key works:
   ```bash
   echo "PasswordAuthentication no" | sudo tee /etc/ssh/sshd_config.d/10-vaultspace.conf
   sudo systemctl reload ssh
   ```

Later updates: copy the new `server` folder to `~/vaultspace/server` on the VM and run
`sudo bash ~/vaultspace/server/deploy/update.sh` (the old version is kept in `/opt/vaultspace/server.old`).
