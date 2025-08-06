"""
Infrastructure Agent - gevent monkey patcher
Copyright (C) 2003-2025 ITRS Group Ltd. All rights reserved
"""
import gevent.monkey

gevent.monkey.patch_all()

patched: bool = True
