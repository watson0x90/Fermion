# Roadmap

Ideas that may be built. None of them is promised, and the order is not fixed. If one matters to you, open an issue and say what you would use it for.

| Idea | What it would do |
| --- | --- |
| **Symbol loading** | Load debug symbols (PDB on Windows) for a module, so that backtraces, Disassembly and References show real function names in binaries that export little. |
| **Session report** | Write the hooks, names, bookmarks and findings of a session to one document. |
| **Notebook** | Keep notes and REPL snippets beside a session, saved with the workspace. |
| **Instruction trace** | Record the instructions a thread executes between two points. |
| **Structure patterns** | Lay a structure definition over memory in the hex view, with each field named and decoded. |
| **CodeShare** | Browse Frida CodeShare and load a script from it. Needs network access. |
| **Target file access** | List and read files on the target's file system, mostly for remote devices. |

## Not tested yet

- **macOS.** Packages are built, unsigned, and have not been run.
- **Linux.** The tests that attach to a process cannot run in continuous integration, so the Inspector's watch, heap, strings and references views are covered there by unit tests only.
