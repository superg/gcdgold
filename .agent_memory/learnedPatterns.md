# Learned patterns

- PSX raw data tracks can mix Mode 2 XA Form 1 and Form 2 sectors even when the ISO filesystem exposes 2,048-byte logical blocks.
- In the reference image, system-area sectors 0–11 are Form 1 and sectors 12–15 are zero-payload Form 2 with computed EDC. The compact system payload is therefore 24,576 bytes after trailing-zero trimming.
- Raw reconstruction must preserve XA subheader semantics independently from ISO 9660 logical content.
- Full-image mismatches are regression-test inputs: identify the responsible byte-level rule, add a failing focused test, and only then fix it.
- `ecmlib` reports a completely zero raw tail as `Mode2Gap` before considering XA-gap semantics. Treat both `Mode2Gap` and `Mode2XaGap` as the reproducible zero XA tail when the XA Form bit is clear.
- Conversely, an all-zero Form 2 payload with zeroed EDC is reported as an XA gap; the duplicated subheader's Form bit must take precedence so it remains Form 2.
- Exact reference layout depends on preserving directory-record order separately from physical file extent order. The sample directory lists `DUMMY.BIN` first even though its data is physically last.
- A deterministic editable layout can remain exact for the source by fixing the PVD at LBA 16, writing four path-table copies, allocating directories breadth-first, and packing files by captured data order.
- The reference reconstruction reached byte equality after the first classified diff. The tail-classification regression test was added in a failing state before accepting `Mode2Gap` as the zero XA suffix.
