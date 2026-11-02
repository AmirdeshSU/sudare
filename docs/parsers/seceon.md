# Seceon aiSIEM exports: stub

Sudare doesn't ship a Seceon parser because Seceon's alert export layout isn't
publicly documented, and the project only maps documented formats.

Seceon alert exports are JSON, so the generic `json` / `ndjson` parsers already read
them. Field values whose names Sudare recognizes (`src_ip`, `dest_ip`, `user_name`,
`src_host_name`, `dst_host_name`, ...) are typed and masked automatically, and
everything else goes through the regex extractors.

## Contributing a mapping

If you have access to Seceon's own export documentation (not just sample alerts):

1. Write `crates/sudare-core/mappings/seceon.toml` (see `CONTRIBUTING.md`), citing the
   documentation in a comment.
2. Pick `detect.all_keys` that only Seceon exports have.
3. Set `group_key` to the event-type field and `self_fields` to the field naming the
   reporting sensor or host.
4. Add a **synthetic** fixture with documentation IPs and invented names, plus its
   manifest entry.

Never paste a real alert into an issue or PR, even a redacted one.
