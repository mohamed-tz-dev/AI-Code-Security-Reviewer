# Scanner Module

This folder contains the first MVP repository scanner.

Current flow:

1. Create an isolated workspace for each scan.
2. Extract ZIP uploads or clone GitHub repositories.
3. Traverse source files only.
4. Ignore dependency, build, cache, lock, binary, and oversized files.
5. Run deterministic static security rules.
6. Run Python AST rules for `.py` files using the bundled Python scanner.
7. Store normalized vulnerabilities.
8. Calculate a security score.

For the MVP, the scanner must follow these rules:

- Never execute uploaded code.
- Extract each repository into an isolated workspace folder.
- Ignore dependency, build, cache, and binary paths.
- Read files as text only.
- Keep file size limits to avoid memory pressure.
- Store normalized findings in PostgreSQL.

Static rules provide fast, predictable findings and keep code scanning stable without external model dependencies.

AI review is optional and can be enabled with `AI_ANALYSIS_ENABLED=true` using `AI_PROVIDER=openai`, `AI_PROVIDER=ollama`, or `AI_PROVIDER=groq`.
