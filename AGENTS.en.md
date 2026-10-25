# Contributor rules — English reference

[Русский, active instructions](AGENTS.md). This file is a translation for readers;
`AGENTS.md` remains the instruction file loaded by the development agent.

Audit only source files in this directory and purpose-built temporary test data.
Do not enumerate host processes, network interfaces, VPNs, routes or services.
Do not read keys, tokens or configuration in the home directory outside `sandbox`.

Runtime agent rules are in `AGENT_POLICY.md`. Check changes locally with
`python3 -m unittest discover -s tests -v`. Integration checks must use an isolated
namespace with controlled fixtures. If the environment forbids namespaces, record
the limitation in the report; do not disable protection or replace a sandbox check
with an inspection of the host.
