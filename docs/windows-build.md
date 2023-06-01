# Building the Windows Agent
## Table of Contents
1. [Prerequisites](#Prerequisites)
2. [Build Instructions](#Build-Instructions)
3. [Installation](#Installation)

## Prerequisites
* [Python 3.9.x with the `venv` module installed](https://www.python.org/)
* [.NET 3.5 via Windows Server Manager](https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/enable-net-framework-35-by-using-the-add-roles-and-features-wizard)
* [Wix Toolset 3.11.x](https://wixtoolset.org/docs/wix3/)
  * The WiX binaries need to be added to the environment's `PATH` for the build scripts to use them.
* [Microsoft Visual C++ Redistributable](https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist)

## Build Instructions
* Clone the [_infrastructure-agent_](https://github.com/ITRS-Group/infrastructure-agent),
  [_infrastructure-agent-windows-plugins_](https://github.com/ITRS-Group/infrastructure-agent-windows-plugins) and
  [_plugnpshell_](https://github.com/opsview/plugnpshell) repositories.
  ```shell
  git clone https://github.com/ITRS-Group/infrastructure-agent.git
  git clone https://github.com/ITRS-Group/infrastructure-agent-windows-plugins.git
  git clone https://github.com/opsview/plugnpshell.git
  ```
* Enter the infrastructure-agent repository and create symlinks to
  'infrastructure-agent-windows-plugins' and 'plugnpshell'
  ```shell
  mklink /D infrastructure-agent-windows-plugins ..\infrastructure-agent-windows-plugins
  mklink /D plugnpshell ..\plugnpshell
  ```
* Create a Python virtual environment and activate it.
```
# Create a Python virtual environment
python -m venv venv
venv\Scripts\activate.bat
```
* Install Python dependencies
```
pip install -r requirements.txt -c constraints.txt
```
* Run the Windows build batch file.
```
build_windows.bat
```
* The agent should be built and be available in the `src` directory `infrastructure-agent-<version>.msi`.

## Installation
* Execute the Infrastructure Agent Follow MSI.
* Follow the steps on [Installation and Configuration](https://docs.itrsgroup.com/docs/opsview/current/install/opsview-infrastructure-agent-beta-installation/index.html#installation)
  in the Opsview Knowledge Center to finish configuring your agent.
* Once configured, restart the agent via Service Manager or Task Manager, then ensure the service is running.
