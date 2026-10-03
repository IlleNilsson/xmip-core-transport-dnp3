# xmip-core-transport-dnp3

DNP3 transport: one application fragment is one Stream, reassembled from its link frames and transport segments; a Location listens as the outstation or connects as the master. IEEE 1815 over TCP. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

A Receive Location keeps its listener, bound on the first receive (`transport::serving::Serving`): a peer that connects between two receives is queued and taken by the next, where until 2026-09-27 each receive bound a listener of its own and a peer between receives was refused.

## Acknowledgement

The master is answered after the whole receive cycle. It sends a fragment's
last segment as confirmed user data, after a reset of link states once per
connection, and waits for the link's answer, a secondary function code of IEEE
1815-2012 chapter 9: Accepted answers ACK; Refused answers NOT_SUPPORTED
(function 15), the link layer's one permanent answer, which fails the master's
send as permanent so it does not send the fragment again; Failed answers NACK,
which fails the master's send as retryable so it sends the fragment again. A master that sends unconfirmed user data waits for nothing:
such a fragment is at-most-once. A confirmed fragment let go without a
verdict shuts its connection (`transport::answer::Answer`), so the master is
not left waiting and sends it again. Each fragment arrives whole, and a
Receive Location keeps the masters' connections open between their fragments
(`transport::serving::Serving`), taking the next fragment from whichever sends
first; until 2026-10-02 a receive read one master's fragments until it closed.
The confirmed last segment adds one link round trip per fragment, and the
reset one per connection.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
