// A checked-in copy, with one edit. NOT the rule as published.
//
// Source: the appendix of InfoGuard Labs' "Slithering Through the Noise"
// (2026-04-09), the companion to `vipertunnel.yar` beside this file. It
// hunts the same family by the typos its author left in, which is why it
// needs only three of five strings and no class names at all.
//
// THE EDIT: the condition's `vt.metadata.file_type == vt.FileType.PYTHON`
// clause has been removed, and with it the `vt` module it needs. Plain
// YARA cannot evaluate that module. Nothing else is changed: the five
// strings are as published, the `filesize < 60KB` bound is as published,
// and so is the `3 of ($typo*)` count.
//
// Note `$typo4` is shared with `vipertunnel.yar`'s `$exc1`, and that
// `$typo5` is a fragment rather than an identifier: it matches a log
// format string that was written to interpolate a tuple.

rule MALWARE_vipertunnel_typos{
    meta:
        description = "Hunting for ViperTunnel Python Proxies using some left over typos"
    strings:
        $typo1 = "__setatrr__" ascii wide // __setattr__
        $typo2 = "deamon" ascii wide // daemon
        $typo3 = "allow_no_verifing" ascii wide // allow_no_verifying
        $typo4 = "ConnectionTimeoutOccuredError" ascii wide // ConnectionTimeoutOccurredError
        $typo5 = "% ((target" ascii wide // logged as tuple

    condition:
        filesize < 60KB and (
            (3 of ($typo*))
        )
}
