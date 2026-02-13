# 0xeb Tools Marketplace

A Claude Code plugin marketplace for reverse engineering, binary analysis, and general purpose utilities.

## Installation

```
/plugin marketplace add 0xeb/anthropic-xsql-tools-plugin
```

Then browse and install:

```
/plugin menu
```

## Available Plugins

### Reverse Engineering

| Plugin | Description |
|--------|-------------|
| [bnsql](plugins/bnsql/) | SQL interface to Binary Ninja databases |
| [idasql](plugins/idasql/) | SQL interface to IDA Pro databases |

## Troubleshooting

### SSH clone failure during plugin install

If `/plugin install` fails with a `Permission denied (publickey)` error:

```bash
git config --global url."https://github.com/".insteadOf "git@github.com:"
```
