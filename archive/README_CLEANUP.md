# Archive Cleanup Required

The `archive/bloat/` directory contains deprecated code that should be removed.

Some files are owned by root and require elevated permissions to delete.

## To clean up manually:

```bash
sudo rm -rf /home/tachyon/CobaltGraph/archive/bloat/
```

## Deprecated files in this directory:

- `launcher.py` - Old web-based launcher (replaced by `src/core/launcher.py`)
- `orchestrator.py` - Multi-mode orchestrator (features integrated into new launcher)
- `supervisor.py` - Process supervision (kept simple in new launcher)
- Dashboard components - Web interface (not yet implemented in MVP)
- Intelligence modules - Moved to `src/services/`

All useful code from these files has been extracted and integrated into the new unified launcher system.
