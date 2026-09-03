# Learning from pull-request replies

GitHub review feedback is a SaaS-owned loop. There is no feedback-ingest command
and an Actions runner does not keep the durable record.

When `adversary run --github-review` posts inline findings from an authenticated
GitHub Actions session, it registers the review and posted comments with
Adversary Labs. The service polls those threads through its GitHub App, stores new
human replies, and classifies technically explained false positives. Accepted
feedback receives a follow-up in the original thread confirming it was learned.

Before the next review of that repository, the CLI retrieves accepted feedback
memory and adds it to every model-backed adversary request. The model must
revalidate the guidance against the current code. Feedback is repository-scoped,
treated as untrusted quoted data, and does not become a blind suppression rule.

The SaaS stores the posted review comment, package/rule/finding provenance, the
human reply, classification, learned guidance, and acknowledgement state. It does
not upload repository source files or diffs for this feature.
