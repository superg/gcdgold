# Active context

Milestone 1 is implemented as a Rust 2024 library and CLI. `gcdgold extract` parses a raw `MODE2/2352` BIN directly into a versioned YAML manifest, a compact `.system` asset, and an ISO 9660 file tree. `gcdgold build` uses that editable project to recalculate path tables, breadth-first directory layout, file extents, PVD-derived values, XA framing, MSF, EDC, and ECC.

The manifest is authoritative: users may resize, rename, add, remove, or move Level 1 files and directories. Data-order fields preserve original physical file ordering while YAML order preserves directory-record ordering. Source hashes are informational after edits.

The PSX system-area model stores a trimmed contiguous Form 1 payload and regenerates the zero-payload Form 2 suffix. Automatic and explicit Form 1 counts are supported, as are computed and zeroed Form 2 EDC policies.

The supplied 5,174-sector reference image rebuilds byte-for-byte with SHA-1 `5b16aa056dee14eff92891c24ca7cf71d263077d`; its compact 24,576-byte `.system` asset has SHA-1 `df9b3d7f3678ef11ecd606d4c820074381506668`.

Current explicit exclusions are audio/subchannel data, multisession layout, Joliet, Rock Ridge, multi-extent files, XA streaming/interleaving, and nonzero Form 2 system payloads. The verification baseline is 14 passing tests plus clean formatting and Clippy with warnings denied.
