import logging
import time
from functools import wraps

log =  logging.getLogger(__name__)


def timed(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        start_time = time.perf_counter()
        result = func(*args, **kwargs)
        end_time = time.perf_counter()
        log.info(
            "[%s] took [%.1f] sec",
            func.__name__,
            end_time - start_time,
        )
        return result
    return wrapper