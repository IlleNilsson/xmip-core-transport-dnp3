# xmip-core-transport-dnp3

DNP3 transport: one application fragment is one Stream, reassembled from its link frames and transport segments; a Location listens as the outstation or connects as the master. IEEE 1815 over TCP. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
