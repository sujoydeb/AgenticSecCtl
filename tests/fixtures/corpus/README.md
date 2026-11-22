# Seed corpus for detector quality

Inert, labelled test strings for the scanner (`tool_descriptions.jsonl`) and the response inspector (`tool_responses.jsonl`). They contain no working exploit; domains use the reserved `.invalid` and `example.com` names and private test addresses. Format, labelling rules, splits and metrics are defined in `docs/testing/fixtures-and-corpora.md`.

This is a **seed set of 24 descriptions and 16 responses**, enough to start tests and to demonstrate the format. It is far too small to establish precision or recall targets. Non-ASCII characters are stored as JSON escapes so hidden characters stay visible in review.
