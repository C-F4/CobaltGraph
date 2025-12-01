#!/usr/bin/env python3
"""
Optional Panda3D-based 3D globe rendering
Falls back to ASCII if Panda3D is not available
"""

import logging
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from panda3d.core import Point3, Vec3, AmbientLight, DirectionalLight
    from direct.showbase.ShowBase import ShowBase
    from direct.task import Task
    PANDA3D_AVAILABLE = True
except ImportError:
    PANDA3D_AVAILABLE = False
    logger.debug("Panda3D not available - 3D globe disabled")


class Panda3DGlobe:
    """
    Optional 3D globe rendering using Panda3D
    Falls back gracefully if library is not available
    """

    def __init__(self):
        """Initialize Panda3D globe if available"""
        self.available = PANDA3D_AVAILABLE
        self.app = None

        if self.available:
            try:
                self._init_panda()
            except Exception as e:
                logger.warning(f"Failed to initialize Panda3D: {e}")
                self.available = False

    def _init_panda(self) -> None:
        """Initialize Panda3D application"""
        if not PANDA3D_AVAILABLE:
            return

        try:
            # Create application
            class GlobeApp(ShowBase):
                def __init__(self):
                    ShowBase.__init__(self)

                    # Window settings
                    self.set_window_title("CobaltGraph 3D Threat Globe")
                    self.win.set_size(800, 600)

                    # Load models
                    self._setup_scene()

                def _setup_scene(self):
                    """Setup 3D scene"""
                    # Load sphere for globe
                    self.globe = self.loader.loadModel("models/misc/sphere")
                    if self.globe:
                        self.globe.reparentTo(self.render)
                        self.globe.set_scale(2)

                    # Add lighting
                    alight = AmbientLight("ambient")
                    alight.set_color((0.8, 0.8, 0.8, 1))
                    alnp = self.render.attach_new_node(alight)
                    self.render.set_light(alnp)

                    dlight = DirectionalLight("directional")
                    dlight.set_color((1, 1, 1, 1))
                    dlnp = self.render.attach_new_node(dlight)
                    dlnp.set_hpr(45, -45, 0)
                    self.render.set_light(dlnp)

                    # Setup camera
                    self.camera.set_pos(0, 0, 5)
                    self.camera.look_at(0, 0, 0)

                    # Add rotation task
                    self.taskMgr.add(self._rotate_globe, "rotateGlobe")

                def _rotate_globe(self, task):
                    """Rotate globe continuously"""
                    if self.globe:
                        self.globe.set_h(self.globe.get_h() + 30 * globalClock.get_dt())
                    return Task.cont

            # Create instance
            self.app = GlobeApp()
            logger.debug("Panda3D globe initialized successfully")

        except Exception as e:
            logger.warning(f"Failed to setup Panda3D scene: {e}")
            self.available = False

    def is_available(self) -> bool:
        """Check if Panda3D globe is available"""
        return self.available

    def run(self) -> None:
        """Run the Panda3D application"""
        if self.available and self.app:
            try:
                self.app.run()
            except Exception as e:
                logger.error(f"Panda3D globe error: {e}")

    def add_marker(self, lat: float, lon: float, threat: float) -> None:
        """Add a threat marker to the globe"""
        if not self.available or not self.app:
            return

        try:
            # Convert lat/lon to 3D coordinates
            import math
            rad_lat = math.radians(lat)
            rad_lon = math.radians(lon)

            radius = 2.0
            x = radius * math.cos(rad_lat) * math.cos(rad_lon)
            y = radius * math.cos(rad_lat) * math.sin(rad_lon)
            z = radius * math.sin(rad_lat)

            # Create marker (sphere)
            marker = self.app.loader.loadModel("models/misc/sphere")
            if marker:
                marker.reparentTo(self.app.render)
                marker.set_scale(0.05)
                marker.set_pos(x, y, z)

                # Color by threat
                if threat >= 0.8:
                    marker.set_color(1, 0, 0, 1)  # Red
                elif threat >= 0.5:
                    marker.set_color(1, 1, 0, 1)  # Yellow
                else:
                    marker.set_color(0, 1, 0, 1)  # Green

        except Exception as e:
            logger.debug(f"Failed to add marker: {e}")

    def close(self) -> None:
        """Close the 3D globe"""
        if self.app:
            try:
                self.app.destroy()
            except Exception as e:
                logger.debug(f"Failed to close Panda3D: {e}")


def get_panda3d_globe() -> Optional[Panda3DGlobe]:
    """Get a Panda3D globe instance if available"""
    if PANDA3D_AVAILABLE:
        try:
            return Panda3DGlobe()
        except Exception as e:
            logger.warning(f"Failed to create Panda3D globe: {e}")
            return None
    return None
