# Notes

Hand-written prose for the wiki. One Markdown file per executable or launchd
service, linked to the relational data in `data/` by its front matter:

```markdown
---
exe: /usr/libexec/syspolicyd      # normalized path, as in data/executable.csv
vendor: Apple
verdict: expected                 # expected / unknown / suspicious, or your own
---
Free-form Markdown: what it is, why it runs, links.
```

Use `service: system/com.apple.foo` (a label from `data/service.csv`) instead
of `exe:` for a launchd service note. Files go in `notes/executables/` or
`notes/services/`. The file name doesn't matter, but the wiki's "No note yet"
hint suggests one that matches the page.

After editing, run `python3 kb.py wiki`. Notes are also queryable:
`python3 kb.py sql "select exe from note where verdict = 'suspicious'"`.
