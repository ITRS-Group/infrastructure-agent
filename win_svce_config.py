"""
Windows Service Configuration File
Copyright (C) 2003-2023 ITRS Group Ltd. All rights reserved
"""

# ------------------------------------------------------------------------------
# Config.py
#   This file defines information about the service. The first four
# attributes are expected to be defined and if they are not an exception will
# be thrown when attempting to create the service:
#
#   NAME
#       the name to call the service with one %s place holder that will be used
#       to identify the service further.
#
#   DISPLAY_NAME
#       the value to use as the display name for the service with one %s place
#       holder that will be used to identify the service further.
#
#   MODULE_NAME
#       the name of the module implementing the service.
#
#   CLASS_NAME
#       the name of the class within the module implementing the service. This
#       class should accept no parameters in the constructor. It should have a
#       method called 'initialize' which will accept the configuration file
#       name. It should also have a method called 'run' which will be called
#       with no parameters when the service is started. It should also have a
#       method called 'stop' which will be called with no parameters when the
#       service is stopped using the service control GUI.
#
#   DESCRIPTION
#       the description of the service (optional)
#
#   AUTO_START
#       whether the service should be started automatically (optional)
#
#   SESSION_CHANGES
#       whether the service should monitor session changes (optional). If
#       True, session changes will call the method 'session_changed' with the
#       parameters sessionId and eventTypeId.
# ------------------------------------------------------------------------------

NAME = "Infrastructure%s"
DISPLAY_NAME = "Infrastructure %s"
MODULE_NAME = "win_svce_handler"
CLASS_NAME = "WinSvceHandler"
DESCRIPTION = "Infrastructure Agent used to respond to status queries"
AUTO_START = True
SESSION_CHANGES = False
