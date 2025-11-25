"""
GPU Particle Trail System - Real-time traceroute visualization
High-performance particle effects using Panda3D GPU shaders
"""

from panda3d.core import (
    GeomVertexFormat, GeomVertexData, GeomVertexWriter,
    Geom, GeomPoints, GeomNode, NodePath,
    Material, TransparencyAttrib, PointLight,
    LVector3, LVector4, ColorBlendAttrib
)
import numpy as np
import random
import time


class ParticleTrail:
    """
    Represents a single connection's particle trail from source to destination
    """

    def __init__(self, source_pos, dest_pos, color=(0.2, 0.8, 1.0, 1.0), num_particles=50):
        """
        Args:
            source_pos: (x, y, z) starting position
            dest_pos: (x, y, z) ending position
            color: RGBA tuple for particles
            num_particles: Number of particles in trail
        """
        self.source = LVector3(*source_pos)
        self.dest = LVector3(*dest_pos)
        self.color = LVector4(*color)
        self.num_particles = num_particles

        # Particle state
        self.particles = []
        self.progress = 0.0  # 0.0 to 1.0
        self.speed = 0.3  # Progress per second
        self.active = True

        # Create particle geometry
        self.geom_node = None
        self.node_path = None

    def create_geometry(self, parent_node):
        """
        Create GPU-efficient particle geometry
        """
        format = GeomVertexFormat.getV3c4()
        vdata = GeomVertexData('particles', format, Geom.UHDynamic)
        vdata.setNumRows(self.num_particles)

        vertex = GeomVertexWriter(vdata, 'vertex')
        color = GeomVertexWriter(vdata, 'color')

        # Initialize particles along arc path
        for i in range(self.num_particles):
            t = i / self.num_particles
            pos = self._calculate_arc_position(t)
            vertex.addData3(*pos)

            # Fade particles along trail
            alpha = 1.0 - (t * 0.7)
            color.addData4(self.color.x, self.color.y, self.color.z, alpha)

        # Create point primitive
        prim = GeomPoints(Geom.UHDynamic)
        for i in range(self.num_particles):
            prim.addVertex(i)
        prim.closePrimitive()

        geom = Geom(vdata)
        geom.addPrimitive(prim)

        self.geom_node = GeomNode('particle_trail')
        self.geom_node.addGeom(geom)

        self.node_path = parent_node.attachNewNode(self.geom_node)
        self.node_path.setRenderModeThickness(3)  # Particle size
        self.node_path.setTransparency(TransparencyAttrib.MAlpha)
        self.node_path.setBin('fixed', 0)
        self.node_path.setDepthWrite(False)

        # Enable additive blending for glow effect
        self.node_path.setAttrib(ColorBlendAttrib.make(
            ColorBlendAttrib.MAdd,
            ColorBlendAttrib.OIncomingAlpha,
            ColorBlendAttrib.OOne
        ))

    def _calculate_arc_position(self, t):
        """
        Calculate position along arc between source and dest

        Creates a curved path that arcs above the globe surface
        """
        # Linear interpolation
        base_pos = self.source + (self.dest - self.source) * t

        # Add arc height (peaks at midpoint)
        arc_height = 2.0 * (1.0 - abs(2 * t - 1))
        direction = (self.dest - self.source).cross(LVector3(0, 0, 1))
        direction.normalize()

        arc_pos = base_pos + direction * arc_height

        return (arc_pos.x, arc_pos.y, arc_pos.z)

    def update(self, dt):
        """
        Update particle animation

        Args:
            dt: Delta time since last update

        Returns:
            True if still active, False if complete
        """
        if not self.active:
            return False

        self.progress += self.speed * dt

        if self.progress >= 1.0:
            self.active = False
            return False

        # Update particle positions
        if self.geom_node:
            vdata = self.geom_node.modifyGeom(0).modifyVertexData()
            vertex = GeomVertexWriter(vdata, 'vertex')

            for i in range(self.num_particles):
                # Particle position with animation offset
                t = (i / self.num_particles + self.progress) % 1.0
                pos = self._calculate_arc_position(t)
                vertex.setData3(*pos)

        return True

    def cleanup(self):
        """Remove particle trail"""
        if self.node_path:
            self.node_path.removeNode()
        self.active = False


class ParticleTrailSystem:
    """
    Manages multiple particle trails for real-time connection visualization
    Optimized for low CPU usage, GPU-accelerated rendering
    """

    def __init__(self, render_node, max_trails=100):
        """
        Args:
            render_node: Panda3D render node to attach particles to
            max_trails: Maximum concurrent particle trails (memory limit)
        """
        self.render = render_node
        self.max_trails = max_trails
        self.active_trails = []
        self.trail_pool = []

        # Performance tracking
        self.last_update = time.time()

        print(f"[ParticleTrailSystem] Initialized (max: {max_trails} trails)")

    def add_trail(self, source_lat, source_lon, dest_lat, dest_lon,
                  threat_level=0.5, globe_radius=5.0):
        """
        Add a particle trail between two geographic coordinates

        Args:
            source_lat, source_lon: Origin coordinates
            dest_lat, dest_lon: Destination coordinates
            threat_level: 0.0 to 1.0 (affects color)
            globe_radius: Globe radius for coordinate conversion
        """
        # Limit active trails
        if len(self.active_trails) >= self.max_trails:
            # Remove oldest trail
            old_trail = self.active_trails.pop(0)
            old_trail.cleanup()

        # Convert lat/lon to 3D coordinates
        source_pos = self._latlon_to_xyz(source_lat, source_lon, globe_radius, altitude=0.2)
        dest_pos = self._latlon_to_xyz(dest_lat, dest_lon, globe_radius, altitude=0.2)

        # Color based on threat level
        color = self._get_threat_color(threat_level)

        # Create trail
        trail = ParticleTrail(source_pos, dest_pos, color, num_particles=30)
        trail.create_geometry(self.render)

        self.active_trails.append(trail)

        return trail

    def _latlon_to_xyz(self, lat, lon, radius, altitude=0.0):
        """Convert geographic to Cartesian coordinates"""
        import math
        lat_rad = math.radians(lat)
        lon_rad = math.radians(lon)

        r = radius + altitude
        x = r * math.cos(lat_rad) * math.cos(lon_rad)
        y = r * math.cos(lat_rad) * math.sin(lon_rad)
        z = r * math.sin(lat_rad)

        return (x, y, z)

    def _get_threat_color(self, threat_level):
        """
        Get color based on threat level

        Returns:
            (r, g, b, a) tuple
        """
        if threat_level < 0.3:
            # Low threat - cyan
            return (0.2, 0.8, 1.0, 0.9)
        elif threat_level < 0.7:
            # Medium threat - yellow
            return (1.0, 0.8, 0.2, 0.9)
        else:
            # High threat - red
            return (1.0, 0.2, 0.2, 0.9)

    def update(self):
        """
        Update all active particle trails
        Called every frame
        """
        current_time = time.time()
        dt = current_time - self.last_update
        self.last_update = current_time

        # Update trails, remove completed ones
        self.active_trails = [
            trail for trail in self.active_trails
            if trail.update(dt)
        ]

    def clear_all(self):
        """Remove all particle trails"""
        for trail in self.active_trails:
            trail.cleanup()
        self.active_trails.clear()

    def get_active_count(self):
        """Return number of active trails"""
        return len(self.active_trails)

    def set_max_trails(self, max_trails):
        """Update maximum concurrent trails"""
        self.max_trails = max_trails

        # Trim if over limit
        while len(self.active_trails) > max_trails:
            old_trail = self.active_trails.pop(0)
            old_trail.cleanup()
