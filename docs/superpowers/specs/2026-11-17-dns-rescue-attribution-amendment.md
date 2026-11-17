# Amendment: attributing a rescue from a beacon that never learned its name

**Date:** 2026-11-17
**Amends:** `2026-11-12-dns-rescue-channel-design.md`, §5 "Before registration"
and the acceptance table
**Status:** implemented
**Occasion:** Measured in a running server. A rescue record carrying the
*implant* id was filed as unattributable while the server held that very id in
`agents[name]["id"]`. The operator was shown "a stuck beacon nobody can claim"
about a host the server could name.

The implementation was faithful to the design. The design's reasoning covered
one case and the code covered only that case.

---

## 1 What the design said

> **Before registration.** The beacon uses `self._agent_id or
> self._implant_id`. An implant that never reached anything has no agent id, so
> the rescue carries the implant id and the server cannot attach it to an agent
> row. It is still sent and still shown — as an unattributed rescue, which is a
> real and useful thing to see — because a drop-box that never managed to
> register is precisely the case with the least other evidence.

Everything in that paragraph is true of the case it describes: an implant that
has **never** registered has no agent row, so there is nothing to attach it to,
and keeping the record is the right call.

## 2 What it missed

A process that never registered is not the only process without an
`_agent_id`. Measured in the code:

- `_agent_id` is assigned in exactly one place, `beacon.py:_register_https`.
- No other transport sends `action=register`. The DNS, SMB and QUIC paths set
  `_registered`, never the name.
- An implant id is **one per host and stable across restarts** — a known limit
  recorded in `AGENT.md` in its own right.

So take a host that registered last week and whose HTTPS leg is now dead. The
beacon restarts. The agent row from the earlier process is still in the fleet,
holding that host's implant id in `info["id"]`. The new process cannot learn
its fleet name — nothing but HTTPS hands it out — so it stamps the implant id,
and the server compared the record against fleet names only.

That is not an edge case. **It is the shape this channel was built for:** HTTPS
down, DNS the only leg that answers.

## 3 The correction

`_handle_rescue` matches in two passes over the fleet:

1. `fingerprint(agent_id)` — the fleet name, across every agent.
2. `fingerprint(info["id"])` — the implant id, across every agent, skipping any
   record whose id is empty.

A fleet name is tried first and across the whole fleet before any implant id is
considered, because it is the stronger signal: a beacon can only stamp a fleet
name if this server handed it that name in a registration reply. Two bytes of
fingerprint collide once in 65536, and offering a second candidate per agent
doubles that, so when both kinds match the name wins.

An empty id identifies nobody. `fingerprint("")` is a fixed value, so a record
carrying no id would otherwise claim every rescue from a beacon that had not
yet learned who it was — and the first such record in the dict would take all
of them.

This is not a new mechanism in this server. `_handle_beacon` resolves an
implant id to a fleet name for a check-in that arrives without one, and
`_handle_register` does it to recognise a returning host. The rescue path was
the one that did not.

**§5 still holds for the case it describes.** An implant with no agent row
anywhere is still unattributable, still kept, still shown — and the acceptance
row "a rescue from an implant with no agent id is sent and shown unattributed"
now means what it says: *no agent id anywhere in the fleet*, not *no agent id
in this process*.

## 4 A second defect, found by the test for the first

`_handle_rescue` set `info["last_channel"] = "dns"` and then called
`_handle_beacon`, which sets `last_channel = "http"` on every call — by
design, because it cannot tell the HTTPS, SMB and QUIC relays apart on the
agent socket. The rescue path's own mark was therefore overwritten one line
after it was written, on **both** match paths, and had been since the channel
shipped.

Measured before the fix, with an agent whose rescue matched by fleet name:

```
fleet name   -> last_channel='http'  stuck=True
implant id   -> last_channel='http'  stuck=True
```

So the interface showed `http` for a beacon whose only working leg was DNS.
The bookkeeping now runs first and the mark is written after it.

This was not in the brief. It surfaced because a test asserted the state the
handler claimed to produce rather than only the state it was asked about.

## 5 What is not changed

- The beacon is untouched. It could be taught to learn its name from a
  transport other than HTTPS, but nothing other than HTTPS registers, so there
  is no name to learn; that would be a different change to a different layer.
- The record format, the label arithmetic, the latch and the listener are
  untouched.
- The unattributable list keeps its purpose and its cap.
