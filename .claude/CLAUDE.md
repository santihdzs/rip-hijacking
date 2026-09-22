# rip-hijacking

## project
RIP routing-protocol hijacking research. Analyzing captured RIP traffic (with plaintext/simple passwords of varying key sizes) to understand and demonstrate route hijacking against RIP.

## goals
- characterize the RIP traffic in `pcaps/` (versions, auth mode, passkey handling per key size)
- demonstrate a hijacking / route-injection attack against RIP and document how it works
- explain the auth weakness the passkey-size captures expose
- <BLANK: final deliverable — paper, demo, slides? fill in>

## constraints
- cybersecurity coursework (ITESM, 5th semester). scope is the assignment.
- <BLANK: due date>
- <BLANK: lab/environment rules, allowed tooling, any targets that are off-limits>
- do not overwrite or mutate the raw captures in `pcaps/`; treat them as read-only evidence.

## context
- raw evidence: `pcaps/` (6 captures, `rip_passkey_size_{06,07,08}_*.pcap`)
- drop reference material (papers, RFCs, slides→pdf, RIP specs) into `.claude/loom/context/`, read on demand
- <BLANK: course materials, assignment brief, notes repo, or shared drive — name them here>

loom constitution is not repeated here; it loads via the loom-core session hook.
