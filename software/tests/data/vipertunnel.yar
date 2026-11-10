// A checked-in copy, with one edit. NOT the rule as published.
//
// Source: the appendix of InfoGuard Labs' "Slithering Through the Noise"
// (2026-04-09), which documents the Python reverse-SOCKS backdoor this
// repository's tunnel protocol takes its shape from. Reproduced here as
// test data under `software/tests/test_tunnel_yara.py`, which requires
// that our generated artifact does not match it.
//
// THE EDIT: the condition's `vt.metadata.file_type == vt.FileType.PYTHON`
// clause has been removed, and with it the `vt` module it needs. Plain
// YARA cannot evaluate that module -- it exists only inside VirusTotal's
// own scanning -- so the rule as published does not compile here at all.
// Nothing else is changed: the strings are as published, and so is the
// `filesize < 60KB` bound and the three-armed counting logic.
//
// Consequence worth knowing before reading a result: the file-type clause
// was the only thing removed, so this copy is *more* likely to match than
// the original, never less. A "no match" from this file is therefore at
// least as strong a claim as a "no match" from the published rule.

rule MALWARE_vipertunnel {
    meta:
        author = "Evgen Blohm"
        description = "hunting rule for socks5 backdoor aka VIPERTUNNEL"

    strings:
        // Unique Class Names and Functions
        $class1 = "class Wire(" ascii wide
        $class2 = "class Relay(" ascii wide
        $class3 = "class Commander(" ascii wide
        $class4 = "class ControllerCommandConnection" ascii wide
        $class5 = "class MySocket" ascii wide
        $class6 = "class MyServiceSocket" ascii wide
        $class7 = "class Handler" ascii wide

        // Custom Exception Names
        $exc1 = "ConnectionTimeoutOccuredError" ascii wide
        $exc2 = "BadLengthData" ascii wide
        $exc3 = "CloseException" ascii wide
        $exc4 = "ExitException" ascii wide
        $exc5 = "ConnectionClosedError" ascii wide
        $exc6 = "ConnectionResetError" ascii wide
        $exc7 = "ConnectionAbortedError" ascii wide
        $exc8 = "ConnectionRefusedError" ascii wide

        // Logic-specific strings
        $logic1 = "self.must_equal = " ascii wide
        $logic2 = "struct.unpack('BBB', self." ascii wide
        $logic3 = "def _bridge(self):" ascii wide
        $logic4 = "socket.socket = Wire" ascii wide

        // unique variables
        $var1 = "main_flag_to_close" ascii wide
        $var2 = "TIMEOUT_FOR_SOCKET_OPERATION" ascii wide

        // Unique Identifiers
        $user = "AnyLogin" ascii wide
        $secret = "AnyPassword" ascii wide

    condition:
        filesize < 60KB and (
            (3 of ($class*) and 3 of ($exc*)) or
            (2 of ($class*) and 2 of ($exc*) and 1 of ($logic*) and 1 of ($var*)) or
            ($user and $secret)
        )
}
