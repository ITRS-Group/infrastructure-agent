"""
Infrastructure Agent: Unit tests for Process Manager
Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved
"""

import gevent
from agent.processmanager import ProcessManager
from gevent.event import Event
from gevent.lock import BoundedSemaphore
from gevent.exceptions import LoopExit


class ProcStub:
    """Represents the basics of a running process.
    Can be waited on and killed.
    """

    def __init__(self, pid=1, kill_exception=None):
        self.pid = pid
        self.wait_called = 0
        self.kill_called = 0
        self._ev = Event()
        self._kill_exception = kill_exception

    def wait(self):
        self.wait_called += 1
        self._ev.clear()
        self._ev.wait()

    def kill(self):
        self.kill_called += 1
        if self._kill_exception:
            raise self._kill_exception
        self._ev.set()


def test_process_dies(mocker, caplog):
    proc_mock = ProcStub()
    popen_mock = mocker.patch('agent.processmanager.Popen', return_value=proc_mock)
    pm = ProcessManager()
    proc1, lock1 = pm.get_managed_process('test1', 'path1')
    proc1.kill()
    gevent.sleep(0)
    assert "Restarting managed process" in caplog.text
    assert popen_mock.call_count == 2


def test_get_managed_process(mocker):
    def create_proc(*args, **kwargs):
        cl_args = args[0]
        cmd_args.append(cl_args)
        return proc_mock

    proc_mock = ProcStub()
    popen_mock = mocker.patch('agent.processmanager.Popen', side_effect=create_proc)
    pm = ProcessManager()
    cmd_args = []
    proc1, lock1 = pm.get_managed_process('test1', 'path1')
    assert cmd_args[0] == ['path1']
    assert proc1 == proc_mock
    assert isinstance(lock1, BoundedSemaphore)
    popen_mock.assert_called()
    lock1.release()
    gevent.sleep(0)
    proc2, lock2 = pm.get_managed_process('test1', 'path1')
    assert proc2 == proc1


def test_could_not_launch_process(mocker, caplog):
    def test_greenlet():
        pm.get_managed_process('test1', path)

    path = '/some/path'
    mocker.patch('agent.processmanager.Popen', side_effect=Exception())
    pm = ProcessManager()
    g_tester = gevent.spawn(test_greenlet)
    try:
        g_tester.join()
    except LoopExit:
        pass
    assert f"Could not launch the process at '{path}'" in caplog.text


def test_kill_all(mocker):
    p1 = ProcStub(1)
    p2 = ProcStub(2)
    mocker.patch('agent.processmanager.Popen', side_effect=[p1, p2])
    pm = ProcessManager()
    proc1, lock1 = pm.get_managed_process('test1', 'path1')
    proc2, lock2 = pm.get_managed_process('test2', 'path2')
    assert proc1 == p1
    assert proc2 == p2
    assert proc1.wait_called == 1
    assert proc2.wait_called == 1
    pm.kill_all()
    assert proc1.kill_called == 1
    assert proc2.kill_called == 1


def test_kill_failed(mocker, caplog):
    p1 = ProcStub(1, kill_exception=Exception())
    mocker.patch('agent.processmanager.Popen', side_effect=[p1])
    pm = ProcessManager()
    pm.get_managed_process('test1', 'path1')
    pm.kill_all()
    assert "Failed to kill process 'test1' (pid=1)" in caplog.text


def test_kill_no_proc(mocker):
    mocker.patch('agent.processmanager.gevent')
    mocker.patch('agent.processmanager.Event')
    pm = ProcessManager()
    pm.get_managed_process('test1', 'path1')
    assert pm.recycle_all() == 0
    assert pm.kill_all() == 0


def test_recycle(mocker):
    def test_greenlet():
        proc, lock = pm.get_managed_process('test1', 'path1')
        lock.release()
        pm.recycle_all()

    p1 = ProcStub(1)
    p2 = ProcStub(2)
    popen_mock = mocker.patch('agent.processmanager.Popen', side_effect=[p1, p2])
    pm = ProcessManager()
    gevent.spawn(test_greenlet).join()
    assert popen_mock.call_count == 2
    assert p1.wait_called == 1
    assert p1.kill_called == 1
    assert p2.wait_called == 1
    assert p2.kill_called == 0


def test_recycle_failed(mocker, caplog):
    p1 = ProcStub(1, kill_exception=Exception())
    mocker.patch('agent.processmanager.Popen', side_effect=[p1])
    pm = ProcessManager()
    proc, lock = pm.get_managed_process('test1', 'path1')
    lock.release()
    pm.recycle_all()
    assert p1.kill_called == 1
    assert "Failed to recycle process 'test1'" in caplog.text


def test_greenlet_cleanup(mocker, caplog):
    mock_proc = mocker.Mock()
    mocker.patch('agent.processmanager.Popen', return_value=mock_proc)
    error_text = 'wait failed'
    mock_proc.wait.side_effect = Exception(error_text)
    # if kill_except:
    #     mock_proc.kill.side_effect = Exception()
    pm = ProcessManager()
    proc, lock = pm.get_managed_process('test1', 'path1')
    assert error_text in caplog.text
    proc.kill.assert_called()
