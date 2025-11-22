"""
CobaltGraph Supervisor Module
Auto-restart and health monitoring

Responsibilities:
- Monitor watchfloor process health
- Auto-restart on crash
- Exponential backoff on repeated failures
- Max restart limits
- Clean shutdown handling
"""

import time
import logging
from typing import Callable

logger = logging.getLogger(__name__)

class Supervisor:
    """
    Supervisor for auto-restarting CobaltGraph on crashes

    Features:
    - Configurable max restarts
    - Exponential backoff
    - Crash detection vs clean shutdown
    - Health monitoring
    """

    def __init__(self, target_func: Callable, max_restarts: int = 10, restart_delay: int = 5):
        """
        Initialize supervisor

        Args:
            target_func: Function to supervise (watchfloor.start)
            max_restarts: Maximum restart attempts
            restart_delay: Base delay between restarts (seconds)
        """
        self.target_func = target_func
        self.max_restarts = max_restarts
        self.restart_delay = restart_delay
        self.restart_count = 0
        self.running = True

    def start(self):
        """
        Start supervised process with auto-restart

        Runs target_func in a loop, restarting on failure
        up to max_restarts times with exponential backoff.
        """
        logger.info("🤖 Supervisor started")
        logger.info(f"📊 Max restarts: {self.max_restarts}, Base delay: {self.restart_delay}s")

        while self.running and self.restart_count < self.max_restarts:
            try:
                logger.info(f"▶️  Starting supervised process (attempt {self.restart_count + 1})")

                # Run the target function
                self.target_func()

                # If we get here, it was a clean shutdown
                logger.info("✅ Clean shutdown detected")
                break

            except KeyboardInterrupt:
                # User requested shutdown
                logger.info("⏹️  User interrupt - stopping supervision")
                break

            except Exception as e:
                # Crash detected
                self.restart_count += 1
                logger.error(f"💥 Process crashed: {e}")

                if self.restart_count >= self.max_restarts:
                    logger.error(f"❌ Max restarts ({self.max_restarts}) reached - giving up")
                    break

                # Calculate backoff delay
                delay = self.get_restart_delay()
                logger.warning(f"🔄 Restarting in {delay}s... ({self.restart_count}/{self.max_restarts})")
                time.sleep(delay)

        logger.info("🛑 Supervisor stopped")

    def stop(self):
        """Stop supervisor"""
        self.running = False

    def get_restart_delay(self) -> float:
        """
        Calculate restart delay with exponential backoff

        Returns:
            float: Delay in seconds
        """
        # Exponential backoff: delay * (2 ^ restart_count)
        return self.restart_delay * (2 ** min(self.restart_count, 5))
