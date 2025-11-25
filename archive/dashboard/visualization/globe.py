"""
3D Globe Renderer - Panda3D-based Earth visualization
GPU-accelerated rendering with threat overlay support
"""

from direct.showbase.ShowBase import ShowBase
from panda3d.core import (
    AmbientLight, DirectionalLight, PointLight,
    Texture, TextureStage, TransparencyAttrib,
    GeomVertexFormat, GeomVertexData, GeomVertexWriter,
    Geom, GeomTriangles, GeomNode,
    NodePath, LVector3, LVector4,
    Material, ShaderAttrib, Shader
)
from panda3d.core import loadPrcFileData
import numpy as np
import math


# Configure Panda3D for optimal performance
loadPrcFileData('', 'window-title CobaltGraph - 3D Threat Map')
loadPrcFileData('', 'win-size 1920 1080')
loadPrcFileData('', 'fullscreen false')
loadPrcFileData('', 'framebuffer-multisample 1')
loadPrcFileData('', 'multisamples 4')
loadPrcFileData('', 'sync-video false')  # Disable vsync for max FPS


class ThreatGlobe(ShowBase):
    """
    GPU-accelerated 3D Earth globe with threat visualization

    Features:
    - High-resolution Earth texture mapping
    - Dynamic threat heat map overlay
    - Particle trail rendering for connection tracking
    - Optimized for 2GB RAM target
    """

    def __init__(self):
        super().__init__()

        # Performance optimization: disable unnecessary features
        self.disableMouse()

        # Create the globe sphere
        self.globe = self._create_globe()
        self.globe.reparentTo(self.render)

        # Setup camera
        self.camera.setPos(0, -15, 0)
        self.camera.lookAt(self.globe)

        # Setup lighting
        self._setup_lighting()

        # Rotation control
        self.rotation_speed = 5.0
        self.auto_rotate = True
        self.taskMgr.add(self._rotate_globe, "rotate_globe")

        # Threat markers storage
        self.threat_markers = []
        self.connection_lines = []

    def _create_globe(self, radius=5.0, segments=64):
        """
        Create UV sphere for Earth with optimized geometry
        Uses GPU-efficient indexed triangle mesh
        """
        format = GeomVertexFormat.getV3n3t2()
        vdata = GeomVertexData('globe', format, Geom.UHStatic)
        vdata.setNumRows((segments + 1) * (segments + 1))

        vertex = GeomVertexWriter(vdata, 'vertex')
        normal = GeomVertexWriter(vdata, 'normal')
        texcoord = GeomVertexWriter(vdata, 'texcoord')

        # Generate sphere vertices
        for lat in range(segments + 1):
            theta = lat * math.pi / segments
            sin_theta = math.sin(theta)
            cos_theta = math.cos(theta)

            for lon in range(segments + 1):
                phi = lon * 2 * math.pi / segments
                sin_phi = math.sin(phi)
                cos_phi = math.cos(phi)

                # Vertex position
                x = radius * sin_theta * cos_phi
                y = radius * sin_theta * sin_phi
                z = radius * cos_theta

                vertex.addData3(x, y, z)
                normal.addData3(x / radius, y / radius, z / radius)
                texcoord.addData2(lon / segments, lat / segments)

        # Generate triangles
        prim = GeomTriangles(Geom.UHStatic)
        for lat in range(segments):
            for lon in range(segments):
                first = lat * (segments + 1) + lon
                second = first + segments + 1

                prim.addVertices(first, second, first + 1)
                prim.addVertices(second, second + 1, first + 1)

        geom = Geom(vdata)
        geom.addPrimitive(prim)

        node = GeomNode('globe_geom')
        node.addGeom(geom)

        globe_np = NodePath(node)

        # Apply material for realistic appearance
        mat = Material()
        mat.setShininess(20.0)
        mat.setAmbient((0.3, 0.3, 0.4, 1))
        mat.setDiffuse((0.8, 0.8, 1.0, 1))
        mat.setSpecular((0.4, 0.4, 0.5, 1))
        globe_np.setMaterial(mat)

        return globe_np

    def _setup_lighting(self):
        """
        Create atmospheric lighting for the globe
        """
        # Ambient light (space background)
        ambient = AmbientLight('ambient')
        ambient.setColor((0.2, 0.2, 0.3, 1))
        ambient_np = self.render.attachNewNode(ambient)
        self.render.setLight(ambient_np)

        # Directional light (sun)
        sun = DirectionalLight('sun')
        sun.setColor((1.0, 0.95, 0.8, 1))
        sun_np = self.render.attachNewNode(sun)
        sun_np.setHpr(45, -45, 0)
        self.render.setLight(sun_np)

        # Point light for threats (red glow)
        threat_light = PointLight('threat_glow')
        threat_light.setColor((0.8, 0.2, 0.2, 1))
        threat_light.setAttenuation((1, 0.1, 0.01))
        self.threat_light_np = self.render.attachNewNode(threat_light)
        self.threat_light_np.setPos(0, 0, 8)
        # Don't activate by default, only when threats detected

    def _rotate_globe(self, task):
        """
        Smooth globe rotation for visualization
        """
        if self.auto_rotate:
            dt = globalClock.getDt()
            current_h = self.globe.getH()
            self.globe.setH(current_h + self.rotation_speed * dt)
        return task.cont

    def latlon_to_xyz(self, lat, lon, radius=5.0, altitude=0.0):
        """
        Convert geographic coordinates to 3D Cartesian coordinates

        Args:
            lat: Latitude in degrees (-90 to 90)
            lon: Longitude in degrees (-180 to 180)
            radius: Globe radius
            altitude: Height above surface (for threat markers)

        Returns:
            (x, y, z) tuple
        """
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)

        r = radius + altitude
        x = r * math.cos(lat_rad) * math.cos(lon_rad)
        y = r * math.cos(lat_rad) * math.sin(lon_rad)
        z = r * math.sin(lat_rad)

        return (x, y, z)

    def add_threat_marker(self, lat, lon, threat_level, threat_type="unknown"):
        """
        Add a 3D threat marker at geographic location

        Args:
            lat: Latitude
            lon: Longitude
            threat_level: 0.0 to 1.0 (severity)
            threat_type: Classification string
        """
        from panda3d.core import CardMaker

        # Create marker geometry
        cm = CardMaker('threat_marker')
        cm.setFrame(-0.1, 0.1, -0.1, 0.1)
        marker = self.render.attachNewNode(cm.generate())

        # Position at lat/lon
        altitude = 0.1 + (threat_level * 0.5)  # Higher threats float higher
        x, y, z = self.latlon_to_xyz(lat, lon, altitude=altitude)
        marker.setPos(x, y, z)
        marker.setBillboardPointEye()  # Always face camera

        # Color based on threat level
        # Green (low) -> Yellow (med) -> Red (high)
        if threat_level < 0.3:
            color = (0.2, 0.8, 0.2, 0.9)
        elif threat_level < 0.7:
            color = (0.9, 0.7, 0.1, 0.9)
        else:
            color = (0.9, 0.1, 0.1, 0.9)

        marker.setColor(*color)
        marker.setTransparency(TransparencyAttrib.MAlpha)

        self.threat_markers.append({
            'node': marker,
            'lat': lat,
            'lon': lon,
            'level': threat_level,
            'type': threat_type
        })

        return marker

    def clear_threats(self):
        """Remove all threat markers"""
        for marker in self.threat_markers:
            marker['node'].removeNode()
        self.threat_markers.clear()

    def set_rotation_speed(self, speed):
        """Set globe rotation speed (degrees per second)"""
        self.rotation_speed = speed

    def toggle_rotation(self):
        """Toggle auto-rotation on/off"""
        self.auto_rotate = not self.auto_rotate

    def cleanup(self):
        """Clean up resources"""
        self.clear_threats()
        self.destroy()


if __name__ == '__main__':
    # Test the globe renderer
    globe = ThreatGlobe()

    # Add some test threat markers
    globe.add_threat_marker(40.7128, -74.0060, 0.8, "High threat - NYC")  # NYC
    globe.add_threat_marker(51.5074, -0.1278, 0.5, "Medium threat - London")  # London
    globe.add_threat_marker(35.6762, 139.6503, 0.3, "Low threat - Tokyo")  # Tokyo
    globe.add_threat_marker(37.7749, -122.4194, 0.9, "Critical - San Francisco")  # SF

    globe.run()
