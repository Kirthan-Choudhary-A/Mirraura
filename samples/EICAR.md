# EICAR test sample

`samples/eicar.txt` is intentionally **not** committed to this repo and is
gitignored. The EICAR string is the industry-standard antivirus test
signature — any antivirus (Windows Defender included) is *supposed* to
detect and quarantine it on sight. That's correct behavior, not a bug, but
it means the raw file can't survive being committed or cloned on a Windows
machine with real-time protection on: Defender deletes it within seconds of
it touching disk, in any encoding (plain text or base64 — tested, both get
caught).

## Before the "known-bad hash" demo case

1. Add an antivirus exclusion for this repo folder (elevated PowerShell):
   ```powershell
   Add-MpPreference -ExclusionPath "C:\path\to\Mirraura"
   ```
2. Create the file with exactly this content (no trailing newline changes
   the SHA-256, so copy it exactly):
   ```
   X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
   ```
   Save as `samples/eicar.txt`.
3. Verify the hash matches the known-bad entry in
   `verdict-engine/known_bad_hashes.json`:
   ```
   275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0
   ```
4. Upload it through the demo before removing the exclusion, since Defender
   will quarantine the file again the moment the exclusion is lifted.
