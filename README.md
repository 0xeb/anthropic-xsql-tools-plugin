# libxsql Tools Plugin

Claude Code plugin with skills for [libxsql-based](https://github.com/0xeb/libxsql) reverse engineering tools.

## Installation

```bash
# Add the marketplace
/plugin marketplace add https://raw.githubusercontent.com/0xeb/anthropic-xsql-tools-plugin/main/marketplace.json

# Install plugin
/plugin install xsql-tools@0xeb-tools
```

## Skills Included

| Skill | Description | Requires |
|-------|-------------|----------|
| `idasql` | SQL interface to IDA Pro databases | idasql CLI, IDA Pro license |
| `bnsql` | SQL interface to Binary Ninja databases | bnsql CLI, Binary Ninja license |

## Usage

Once installed, the skills are automatically available:

```
"Using idasql, count the functions in test.i64"
"Using bnsql, find strings containing 'error' in malware.bndb"
"Decompile main in C:/path/to/database.i64"
```

## Tool Installation

The skills require the CLI tools installed separately:

- **idasql**: Place `idasql.exe` next to `ida.exe` in your IDA installation, then add IDA directory to PATH
- **bnsql**: Add Binary Ninja DLL directory to PATH, then add `bnsql.exe` to PATH

## Links

- [libxsql](https://github.com/0xeb/libxsql) - Core SQL virtual table framework
- [idasql](https://github.com/allthingsida/idasql) - IDA Pro SQL interface
- [bnsql](https://github.com/0xeb/bnsql) - Binary Ninja SQL interface
