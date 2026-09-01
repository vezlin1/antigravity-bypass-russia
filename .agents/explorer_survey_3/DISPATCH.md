## 2026-09-01T11:58:45Z
Survey Explorer 3 dispatched.
Scope: Interactive In-App Benchmark & Menu (R3) AND Socket / OS Fine-Tuning (R4)
1. CLI and Menu systems (src/ui/menu.rs, src/cli/, etc.) and how Option 5 / interactive speedtest tool should be added.
2. Determine how to implement live testing of:
   - Latency to Gemini API endpoints
   - Time-To-First-Token (TTFT)
   - Real streaming speed in tokens/sec and KB/sec across candidate relays.
3. Investigate Windows / macOS TCP socket fine-tuning (SO_RCVBUF, SO_SNDBUF = 512 KB, TCP_NODELAY, TCP Window Auto-Tuning).
4. Detail all affected files, structs, UI presentation, socket configuration points, platform commands, error handling, and interfaces.
5. Create progress.md and handoff.md.
