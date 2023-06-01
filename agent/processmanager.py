import gevent
import logging
from dataclasses import dataclass
from gevent import greenlet
from gevent.event import Event
from gevent.lock import BoundedSemaphore
from gevent.subprocess import Popen, PIPE

logger = logging.getLogger(__name__)


@dataclass
class ProcessItem:
    """Represents a process and managing greenlet"""
    g_proc: greenlet  # The greenlet managing the process
    proc_event: Event  # Informs when the process is created
    proc_lock: BoundedSemaphore
    proc: Popen = None  # The managed process
    recycling: bool = False


class ProcessManager:
    """Manages named processes, launching, keeping them running and recycling."""

    def __init__(self):
        self._process_items: dict[str, ProcessItem] = {}

    def get_managed_process(self, name: str, path: str) -> tuple[Popen, BoundedSemaphore]:
        """Return the named long-running process (and launch if not running).

        Note: A process lock is automatically taken on calling this method which should be
        released as soon as possible (to allow recycling to operate).
        """
        p_item = self._process_items.get(name)
        if not p_item:
            proc_event = Event()
            proc_lock = BoundedSemaphore(1)  # Only one thing can use the process at a time
            g_proc = gevent.spawn(self._gproxy, self._p_runner, name, path, proc_event)
            logger.info("Creating new managed process: name='%s'", name)
            p_item = ProcessItem(g_proc=g_proc, proc_event=proc_event, proc_lock=proc_lock)
            self._process_items[name] = p_item
        p_item.proc_event.wait()  # Wait for the process to be created
        p_item.proc_lock.acquire()
        return p_item.proc, p_item.proc_lock

    def kill_all(self) -> int:
        """Kill all maintained processes"""
        kill_count = 0
        for p_name, p_item in self._process_items.items():
            gevent.kill(p_item.g_proc)
            if p_item.proc:
                p_key = f"'{p_name}' (pid={p_item.proc.pid})"
                logger.info("Killing process %s", p_key)
                try:
                    p_item.proc.kill()
                    kill_count += 1
                except Exception as ex:
                    logger.error("Failed to kill process %s: %s", p_key, ex)
        self._process_items.clear()
        return kill_count

    def recycle_all(self) -> int:
        """Recycle all maintained processes.
        Warning: Any held process references will become invalid
        """
        recycled_count = 0
        for p_name, p_item in self._process_items.items():
            if p_item.proc and p_item.proc_lock.acquire():
                logger.debug("Killing process '%s' (pid=%d) for recycling", p_name, p_item.proc.pid)
                p_item.recycling = True
                try:
                    p_item.proc.kill()
                    p_item.proc_event.clear()  # Don't wait for the greenlet to do this
                    recycled_count += 1
                except Exception as ex:
                    logger.error("Failed to recycle process '%s': %s", p_name, ex)
                finally:
                    p_item.proc_lock.release()
        return recycled_count

    def _gproxy(self, fn, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as ex:
            logger.exception(ex)

    def _p_runner(self, name: str, path: str, proc_event: Event):
        p_item: ProcessItem = self._process_items[name]
        try:
            while True:
                try:
                    p_item.proc = Popen([path], stdin=PIPE, stdout=PIPE, stderr=PIPE)
                except Exception as e:
                    raise Exception(f"Could not launch the process at '{path}'") from e
                proc_event.set()  # Indicate that we have a process
                p_key = f"'{name}' (pid={p_item.proc.pid})"
                logger.info("Waiting on launched managed process %s", p_key)
                p_item.proc.wait()
                proc_event.clear()  # The process is gone
                p_item.proc = None
                if p_item.recycling:
                    p_item.recycling = False
                    logger.info("Recycling managed process %s", p_key)
                else:
                    logger.warning("Restarting managed process %s that finished early", p_key)
        except Exception as ex:
            # Something nasty happened. Attempt to clean up before exiting
            if p_item.proc:
                p_item.proc.kill()
            self._process_items.pop(name, None)
            raise ex
