// Every match here is decisive (Compromised, detonation skipped -- see
// static_triage.py), so each rule must stay specific enough that a benign
// script can't trip it.

rule Shell_Base64_Decode_Payload
{
    meta:
        severity = "medium"
        description = "Long base64 blob decoded inside the script -- hidden-payload unpacking"
    strings:
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
        $dec1 = "base64 -d"
        $dec2 = "base64 --decode"
        $dec3 = "base64 -D"
    condition:
        // Not $b64 alone: a 64-char sha256 checksum or any long identifier
        // matches that regex, which would condemn ordinary scripts unrun.
        $b64 and any of ($dec*)
}

rule Shell_Pipe_To_Shell
{
    meta:
        severity = "high"
        description = "Remote script piped straight into a shell (curl|bash, wget|sh)"
    strings:
        $pipe = /(curl|wget)[^\n|]*\|[ \t]*(sudo[ \t]+)?(ba|da|z|k)?sh\b/
    condition:
        $pipe
}

rule Credential_File_Read
{
    meta:
        severity = "high"
        description = "References a credential file (/etc/shadow or an SSH private key)"
    strings:
        $shadow = "/etc/shadow"
        // Private keys only: the name must end there, so id_rsa.pub (a
        // public key plenty of setup scripts read) doesn't match.
        $key = /\/\.ssh\/id_(rsa|ed25519)([^.A-Za-z0-9_]|$)/
    condition:
        any of them
}
