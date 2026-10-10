# Security policy

## Reporting a vulnerability

Report security problems privately through GitHub's **Report a vulnerability** button
(Security tab → Advisories). Do not open a public issue. Include the commit, the profile, and a
reproduction that uses synthetic or public data only. Expect an acknowledgement within 7 days.

## What counts

Gumshoe processes untrusted evidence. These are in scope and taken seriously:

- anything that lets content inside an evidence image **write outside the case directory**,
  execute code on the analysis host, or alter the evidence mount (path traversal in export or
  unpack, unsafe deserialization, shell injection through file names, parser crashes that can be
  steered);
- anything that lets a **citation point at something that was not retrieved**, or lets a custody
  log edit go undetected;
- network access from any command other than the online prep script.

Out of scope: vulnerabilities in the external tools Gumshoe drives (UAC, Loki, Chainsaw, GoAccess,
MariaDB, Ollama) — report those upstream — and model output quality.

## Handling evidence safely

- Run Gumshoe on an isolated analysis host. Mount evidence read-only (`gumshoe verify` enforces this
  in mount mode).
- Never attach evidence, findings, or screenshots of them to issues or pull requests.
- The MariaDB review starts a database server on a **copy** of the datadir with networking disabled;
  keep it that way.
