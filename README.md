# ctxpack

**Pack a project into one file to paste into an AI assistant, without leaking your secrets.** A plain `cat *` hands an assistant your
`.env`, your keys and every lock file. ctxpack gives it the whole picture (file tree plus each file in a clearly delimited block)
and leaves the dangerous parts out.

```
$ ctxpack myproject -o packed.md
ctxpack: packed 3 file(s), about 112 tokens (estimate), source: git
ctxpack: left out as likely secrets: .env
ctxpack: redacted: api-key x1
ctxpack: skipped: 1 lock file
```

Offline, read-only, standard library only.

## Install and use

```bash
pip install git+https://github.com/TPOALOS/ctxpack          # or copy ctxpack.py
ctxpack .                                  # to stdout
ctxpack . -o packed.md                     # to a private file (mode 600, never overwrites without --force)
ctxpack . --max-tokens 60000               # keep it inside a context window (README first, then shallow files)
ctxpack . --format xml --header "Review this project for race conditions."
ctxpack . --list                           # dry run: what would be packed, and what is left out and why
ctxpack . --exclude 'tests/*' --exclude '*.md'
```

## What it does for you

- **Respects `.gitignore`** (asks `git`, or reads the file itself with `--no-git`) and always skips dependency, build and cache folders.
- **Leaves out files that hold secrets**: `.env*` (except `.env.example`), private keys, `*.pem`, credentials files, Terraform state and
  variables, `.npmrc`, `.pypirc`, `.aws/credentials`. They are listed in the summary, never in the output.
- **Redacts secrets inside code**: private key blocks, AWS and GitHub tokens, API keys, JWTs, `password = "..."` values, passwords in
  URLs become `[REDACTED:kind]` (placeholders such as `your_key_here` and `${TOKEN}` are left alone).
- **Strips invisible Unicode** (zero-width characters, text-direction controls, the 'tag' block that can spell hidden instructions) and
  tells you how many it removed.
- **Skips** binaries, lock files, files over 200 KB (`--max-file-size`), symlinks and unreadable files.
- **Frames the content as data**: every pack opens with a notice that instructions inside the files are text to analyse, not orders.
- Markdown fences grow when a file contains backticks, and XML output is fully escaped, so file content cannot break out of its block.

Exit codes: `0` packed, `1` packed but the budget left files out, `2` usage error.

## Limits

Redaction is pattern based and catches the common token shapes, not every secret: read the output before you paste it somewhere you
do not control, and rotate anything that was ever committed. The token figures are rough estimates (about 3.6 characters per token).

## Tests

```bash
python3 -m unittest -v
```

## License

MIT (c) TPOALOS

---

**More tools by [TPOALOS](https://github.com/TPOALOS):** [tokcount](https://github.com/TPOALOS/tokcount) · [cmdguard](https://github.com/TPOALOS/cmdguard) · [mcpaudit](https://github.com/TPOALOS/mcpaudit) · [all 51 tools](https://tpoalos.github.io)
