# SQL Schemas

## Catalogue

1. [wordlist.sqlite3](wordlist.sqlite3) - for all wordlist files (provided to the CLI using the `--wordlist` option).

- Table `wordlist`:
  - `id`: An incremental index in the continuous range [1, max].
  - `word`: A word for the wordlist.
