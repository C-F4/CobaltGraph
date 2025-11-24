# Archived Dashboard Files

**Date Archived**: 2025-11-23
**Reason**: Replaced with Enhanced Terminal UI using Textual + Rich

---

## Contents

This directory contains the original 3D visualization dashboard that was implemented in the `main` branch and later removed during the "clean prototype" refactoring.

### Files

**dashboard_integration.py** (5.8 KB)
- Dashboard backend integration
- Web server setup
- API endpoints

**visualization/__init__.py** (272 bytes)
- Visualization module initialization

**visualization/globe.py** (8.3 KB)
- 3D Earth globe renderer using Panda3D
- GPU-accelerated visualization
- Real-time threat overlay
- ~260 lines of production code

**visualization/particles.py** (8.2 KB)
- Particle effects system
- Animated threat indicators
- GPU-based particle rendering
- ~264 lines of production code

---

## Why These Were Archived

### Original Dashboard (main branch)
- **Tech Stack**: DearPyGUI + Panda3D + Flask
- **Features**: 3D globe, particle effects, web interface
- **Size**: ~1,900 lines of code total
- **Dependencies**: Heavy GPU libraries (OpenGL 3.3+)
- **Memory**: ~500MB for GPU buffers
- **Attack Surface**: HTTP/HTTPS web server

### Replacement: Enhanced Terminal UI
- **Tech Stack**: Textual + Rich (Python stdlib focused)
- **Features**: Live tables, ASCII charts, interactive TUI
- **Size**: ~450 lines of code
- **Dependencies**: Minimal (just rich + textual)
- **Memory**: <50MB
- **Attack Surface**: Zero (terminal-only)

---

## Architecture Decision

**Decision**: Replace GPU-based web dashboard with terminal-only UI

**Rationale**:
1. **Security**: Eliminate HTTP attack surface
2. **Simplicity**: 76% code reduction (1,900 → 450 lines)
3. **Compatibility**: Works over SSH, no GPU required
4. **Performance**: Lower memory usage, faster startup
5. **Focus**: Security-first approach aligns with CobaltGraph mission

**Trade-offs**:
- ❌ No 3D globe visualization
- ❌ No GPU-accelerated graphics
- ❌ No browser-based interface
- ✅ Maximum security (zero web ports)
- ✅ Works in air-gapped environments
- ✅ SSH-friendly remote operation
- ✅ Minimal dependencies

---

## Restoration Instructions

If you need to restore the 3D dashboard:

### Option 1: Restore from Archive
```bash
# Copy files back to src/
cp archive/dashboard/dashboard_integration.py src/core/
cp -r archive/dashboard/visualization src/

# Install dependencies
pip3 install dearpygui>=1.10.0 panda3d>=1.10.14 numpy pillow

# Update launcher to include web option
```

### Option 2: Restore from Git History
```bash
# Files exist in main branch
git show main:src/core/dashboard_integration.py
git show main:src/visualization/globe.py
git show main:src/visualization/particles.py

# Restore specific files
git checkout main -- src/core/dashboard_integration.py
git checkout main -- src/visualization/
```

### Option 3: Use Main Branch
```bash
# Switch to main branch (has full dashboard)
git checkout main

# Run with web interface
python3 start.py --interface web --port 8080
```

---

## Technical Details

### 3D Globe Implementation (globe.py)

**Features**:
- UV sphere mesh generation (optimized geometry)
- High-resolution Earth texture mapping
- Dynamic lighting (ambient + directional)
- Camera controls (rotation, zoom)
- Threat marker overlays
- Connection path rendering
- GPU shader support

**Performance**:
- Target: 60 FPS
- Memory: ~300MB (textures + meshes)
- GPU: OpenGL 3.3+ required
- Resolution: 1920x1080 default

### Particle System (particles.py)

**Features**:
- GPU-instanced particle rendering
- Billboard sprites
- Color interpolation
- Lifetime management
- Force fields and attractors
- Emission patterns

**Performance**:
- Max particles: 10,000
- Memory: ~200MB
- GPU: Compute shader support

---

## Migration Path

The Enhanced Terminal UI provides equivalent functionality in a terminal-friendly format:

| Old Dashboard | New Enhanced Terminal UI |
|--------------|--------------------------|
| 3D globe with connections | Live connection DataTable |
| Particle threat effects | ASCII threat bars + sparklines |
| Web-based charts | Rich panels with progress bars |
| Mouse navigation | Keyboard navigation |
| GPU rendering | Terminal rendering |
| Browser required | Terminal only |

---

## Status

**Current System**: Enhanced Terminal UI (Textual + Rich)
**Archived System**: 3D Dashboard (DearPyGUI + Panda3D)
**Main Branch**: Still has full 3D dashboard implementation
**Clean-Prototype Branch**: Terminal-only, no web interface

---

**Archived Dashboard is fully functional and can be restored if needed.**
