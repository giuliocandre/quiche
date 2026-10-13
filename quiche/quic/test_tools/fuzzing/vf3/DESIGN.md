# vf3-style syntactic, stateful fuzzer for the QUICHE HTTP/3 client

Scope: `QuicSpdyStream` / `QuicSpdyClientStream`, `QuicCryptoClientStream`
(+ `TlsClientHandshaker`), `QuicSpdyClientSessionBase` /
`QuicSpdyClientSession`, and the HTTP/3 client path they form.

## 1. What the slides describe

Four slides from the OAIC talk (the only public material found):

1. **Syntactic fuzzing, "fragile inputs tend to break".** The grammar is a
   graph with enough information to fuzz one field precisely without
   corrupting the others (lengths, offsets, checksums are recomputed). The
   graphs are compiled into optimized tables. Generator throughput is the
   headline number: 3.55M HTTP/1.1 inputs/s vs 2.3M for libprotobuf-mutator
   and 1.7M for Jackalope.
2. **Visualizing an input.** An input is a *path through states and
   grammars*: each state (open, mmap, munmap) owns a grammar subgraph and the
   engine's job is to find paths across them. Inputs are sequences of typed
   operations, not byte blobs.
3. **Control plane.** All of the data plane is graphs, so controls are *graph
   edits*. When the fuzzer is stuck: gather context (coverage, source), ask an
   LLM, apply graph edits. Inputs + harness + controls = a *campaign*.
4. **Targeting code and patches.** The LLM adds a subgraph to an existing
   grammar at a given state to reach specific code. Every field has
   contextual mutations (lengths, offsets, strings, cookies, encodings) and
   mutations can carry payloads.

No code, paper, or input format for vf3 is public, so everything below is a
reimplementation of the architecture, with the details filled in for QUIC.

## 2. Architecture

```
 grammar files (data)        state machine (data)
   http3.g  qpack.g  tls.g     client_states.g
          \        |          /
           v       v         v
        +------------------------+      graph edits (JSON patch)
        |  loader + validator    | <------------------------------+
        |  compile -> tables     |                                |
        +-----------+------------+                                |
                    |                                             |
        +-----------v------------+     +------------------+       |
        |  generator / mutator   |---->| op sequence (IR) |       |
        |  (typed tree, tables)  |<----|  = one input     |       |
        +-----------+------------+     +--------+---------+       |
                    | LLVMFuzzerCustomMutator    | serialize      |
        +-----------v----------------------------v---------+      |
        |  Centipede / libFuzzer: corpus, SanCov feedback,  |     |
        |  crash handling, parallelism                      |     |
        +-----------+---------------------------------------+     |
                    | LLVMFuzzerTestOneInput                      |
        +-----------v------------+                                |
        |  Http3ClientHarness    |  state features -> SanCov      |
        |  (session-level)       |                                |
        +-----------+------------+                                |
                    | coverage, stall detection, source context   |
        +-----------v------------+                                |
        |  control plane (py)    |--------------------------------+
        |  llm -> graph edits    |
        +------------------------+
```

### 2.1 Harness: `Http3ClientHarness` (C++, `quiche/quic/test_tools/fuzzing/vf3/`)

Built from the fixtures in `quic_spdy_client_session_test.cc` and
`quic_crypto_client_stream_test.cc`, which already do the hard part:

* `PacketSavingConnection` (a `MockQuicConnection`): real `QuicConnection`
  logic for alarms, packet creation, and flow control, with writes captured
  instead of sent. `MockAlarmFactory` lets the harness fire alarms
  deterministically, so timeouts are a reachable state.
* `TestQuicSpdyClientSession` over `QuicSpdyClientSession` with
  `MockQuicSpdyClientStream` or the real `QuicSpdyClientStream`.
* `crypto_test_utils::HandshakeWithFakeServer` for the real TLS handshake when
  the input does not fuzz the handshake itself.

Inputs are injected **at the session layer**, bypassing packet crypto:
`QuicSession::OnStreamFrame`, `OnCryptoFrame`, `OnRstStream`,
`OnStopSendingFrame`, `OnWindowUpdateFrame`, `OnGoAway`, `OnMaxStreamsFrame`,
`OnStreamsBlockedFrame`, `OnNewTokenFrame`. This is exactly the surface the
four target classes consume, it needs no decryption, and it runs at
microseconds per op. (`QuicConnection` and `QuicFramer` are out of scope and
have their own fuzzers.)

Harness op vocabulary (the "terminals" the state machine emits):

| op | lands in |
|---|---|
| `StreamData{stream_id, offset, bytes, fin}` | request stream (`QuicSpdyClientStream`), server control stream, QPACK encoder/decoder streams, unknown unidirectional streams, pending streams |
| `CryptoData{level, offset, bytes}` | `QuicCryptoClientStream` -> BoringSSL -> `TlsClientHandshaker` |
| `RstStream`, `StopSending`, `ResetStreamAt`, `MaxStreamData`, `MaxStreams`, `StreamsBlocked`, `GoAway`, `NewToken` | session / stream state machines |
| `ClientRequest{headers, body, fin}`, `ClientWrite`, `ClientReset`, `ClientReadBody{n}` | application-side stimulus; the client's reaction depends on it |
| `AdvanceTime{us}`, `FireAlarm{kind}` | alarms, idle/handshake timeouts, retransmission paths |
| `Handshake{real \| fuzzed}` | either runs the fake server to completion or hands the TLS flight to the grammar |

Oracles: ASan/UBSan, `QUICHE_DCHECK` (debug build), `QUIC_BUG` (hooked to
abort in the fuzz build), connection close with an *internal* error code,
and harness-level invariants (stream count vs limits, flow-control windows,
no callbacks on closed streams).

### 2.2 Grammar IR and tables

A grammar is a directed graph in a text file (protobuf text or JSON), not C++:

* **Node types:** `seq`, `choice{weights}`, `repeat{min,max}`, `varint`,
  `uint{bits}`, `bytes{len_ref}`, `string{charset}`, `enum{values}`,
  `length_of{target}`, `offset_of{target}`, `ref{grammar,node}`, `state_ref`.
* **Field tags** drive contextual mutators: `stream_id` (parity/direction
  aware), `qpack_index` (static/dynamic table aware), `varint` (boundary
  values 2^6/2^14/2^30/2^62-1, reserved encodings), `length` (recompute vs
  off-by-one vs huge), `http_header` (name/value payload dictionaries),
  `setting_id`, `frame_type` (reserved 0x1f*n+0x21 greasing, HTTP/2-only
  types that HTTP/3 must reject), `error_code`.
* **Compile step** flattens the graph into arrays (node table, edge table,
  weight CDFs, mutator dispatch table) so generation and mutation are table
  walks with no allocation on the hot path. This is the "graphs ->
  optimized tables" claim; we measure it with a standalone generator
  benchmark binary (inputs/s and MB/s, like the slide's table).

Grammars needed for this scope:

| grammar | source of truth in repo |
|---|---|
| HTTP/3 frames (DATA, HEADERS, SETTINGS, GOAWAY, MAX_PUSH_ID, PRIORITY_UPDATE, ORIGIN, ACCEPT_CH, METADATA, WEBTRANSPORT_STREAM, unknown/reserved) | `quic/core/http/http_frames.h`, `http_decoder.cc`, `quic_receive_control_stream.cc` |
| Unidirectional stream types (control, push, QPACK enc/dec, WebTransport, unknown) | `quic_spdy_session.cc` `ProcessPendingStreamType` path |
| QPACK: header block (static/dynamic refs, Huffman, literals) and encoder-stream instructions (insert w/ name ref, w/o ref, duplicate, set capacity) | `quic/core/qpack/` |
| HTTP semantics: response pseudo-headers, status codes, 1xx interim responses, trailers, content-length vs DATA mismatch, CONNECT/CONNECT-UDP, capsules | `quic_spdy_stream.cc` |
| TLS 1.3 server flight (ServerHello, HRR, EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket) and the `quic_transport_parameters` extension | BoringSSL; `quic/core/crypto/transport_parameters.cc`; `tls_client_handshaker.cc` |
| Transport frames (RST_STREAM, STOP_SENDING, MAX_STREAM_DATA, GOAWAY, NEW_TOKEN, MAX_STREAMS, STREAMS_BLOCKED, RESET_STREAM_AT) as typed structs, not bytes | `quic/core/frames/` |

### 2.3 State machine

`client_states.g` describes which grammars are legal in which state and which
ops move between states:

```
Init --CryptoConnect--> ServerFlight --Finished--> Handshaked
Handshaked --server control stream SETTINGS--> ControlOpen
ControlOpen --ClientRequest--> RequestOpen(n) --HEADERS--> Headers(n)
Headers(n) --DATA*--> Body(n) --trailers|fin|RST--> Done(n)
any --GoAway--> Draining ; any --FireAlarm(idle)--> Closed
```

One input = a path: a list of `(state, op)` pairs. The generator picks the
next edge from the table, then generates the op from that state's grammar.
Mutators operate on the typed tree: swap a frame, duplicate an op, re-order
within the state's allowed set, mutate one field with its contextual
mutator, splice a subpath from another corpus entry at the same state. Lengths
and offsets are re-derived on serialization so the input stays well-formed
except where a mutator deliberately breaks it.

### 2.4 Feedback

* **Edge + cmp coverage** from `-fsanitize-coverage=inline-8bit-counters,
  pc-table,trace-cmp` via Centipede (already pulled in with `fuzztest`).
* **State features:** the harness exports `(handshake_state, encryption_level,
  n_open_streams, control_stream_state, qpack_dynamic_table_size_bucket,
  last_error_code)` as synthetic coverage so the scheduler rewards new state
  combinations, not just new edges.
* **Stall detection** for the control plane: no new feature for N execs or
  T minutes, per state.

### 2.5 Control plane (Python, out of the fuzzing loop)

1. Detect a stall; collect: coverage report (`llvm-cov` with per-function
   counts for the target files), the uncovered branches nearest to covered
   ones, the current grammar, the current state, recent crash/dedup stats.
2. Ask the LLM for **graph edits only**: add a subgraph (new frame layout,
   new value dictionary), reweight a choice, add a mutator payload, add a
   state edge. Output is a JSON patch against the grammar file.
3. Validate the patch (loader rejects unknown node types, cycles without a
   `repeat` bound, unresolved refs), apply, hot-reload the tables, resume.
4. Every edit is logged with the coverage delta it produced, so useful edits
   can be kept in the grammar permanently.

Targeting a patch (slide 4): feed the diff of a change in
`quic_spdy_stream.cc` and the surrounding functions, ask for a subgraph that
reaches it from the nearest state, and pin the campaign to that state.

## 3. Build and integration

* Bazel 8.2.1 (`.bazelversion`), clang, C++20. Add a `fuzz` config to
  `.bazelrc` (sanitizers, `-fsanitize-coverage`, `-DQUIC_BUG_ABORTS`-style
  hook) and a `vf3` package with `cc_library` engine, `cc_binary` harness,
  and the generator benchmark.
* Engine exposes `LLVMFuzzerCustomMutator` / `LLVMFuzzerCustomCrossOver` so
  the same binary runs under libFuzzer or Centipede. The corpus format is the
  serialized op sequence (varint-tagged), readable by a `vf3_print` tool that
  dumps a failing input as a frame list for bug reports.
* **TLS handshake fuzzing needs BoringSSL built with
  `BORINGSSL_UNSAFE_FUZZER_MODE`** (deterministic RNG, signature and MAC
  checks disabled). The BCR `boringssl` module does not expose that as a flag;
  it needs a `--per_file_copt` or a module patch. Until then the crypto stream
  can only be fuzzed on transport parameters (parsed by QUICHE, reachable
  through the fake server) and on post-handshake messages.

## 4. Milestones

| # | deliverable | done when |
|---|---|---|
| 0 | `fuzz` Bazel config, Bazel available in the environment, existing fuzzers build and run under ASan, baseline coverage of the four target files recorded | numbers in a table |
| 1 | `Http3ClientHarness` with the op vocabulary above, deterministic replay, real handshake via fake server, a unit test that drives one request end to end | test passes under ASan |
| 2 | grammar IR, loader, table compiler, generator, serializer; HTTP/3 + QPACK + transport-frame grammars; generator benchmark | benchmark number; every generated op is accepted by the harness or rejected for a deliberately broken field |
| 3 | state machine + mutators + Centipede integration + state features + `vf3_print` | 24h campaign with coverage of target files above baseline, crash triage pipeline |
| 4 | TLS flight + transport parameter grammar, BoringSSL fuzzer mode | handshake states reachable from fuzzed flights |
| 5 | control plane: stall detector, context gatherer, LLM graph-edit loop, edit ledger | an LLM edit measurably lifts coverage on a stalled state |
