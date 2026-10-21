rule Shell_Dev_TCP_Redirect
{
    meta:
        severity = "medium"
        description = "Bash /dev/tcp redirection -- classic reverse-shell/backconnect pattern"
    strings:
        $devtcp = "/dev/tcp/"
    condition:
        $devtcp
}

rule Shell_Sensitive_Write
{
    meta:
        severity = "low"
        description = "Shell script references a system-sensitive path"
    strings:
        // Not "/bin/" -- every script's own "#!/bin/bash" shebang would
        // match that, making the rule fire on every sample.
        $etc = "/etc/"
    condition:
        $etc
}
