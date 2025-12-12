import time
import random
from .config import JITTER_ENABLED

def apply_traffic_shaping() -> None:
    if JITTER_ENABLED:
        time.sleep(random.uniform(0.001, 0.010))

# تصدير صريح
__all__ = ['apply_traffic_shaping']