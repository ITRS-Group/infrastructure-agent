# Building the Linux Agent
## Table of Contents
1. [Prerequisites](#Prerequisites)
2. [Build Instructions](#Build-Instructions)
3. [Installation](#Installation)

## Prerequisites
* [Python 3.9.x with the `venv` module installed](https://www.python.org/)
  * For Ubuntu sytems, these can be found in the [deadsnakes PPA](https://launchpad.net/~deadsnakes/+archive/ubuntu/ppa).
    ```shell
    apt install python3.9 python3.9-venv python3.9-dev
    ```
  * For other distributions, you may have to [build Python from source](https://devguide.python.org/getting-started/setup-building/).
* [GNU Make](https://www.gnu.org/software/make/)
* [CMake](https://cmake.org/)
* [GCC](https://gcc.gnu.org/)
* [Perl](https://www.perl.org/) with [`Module::Build`](https://metacpan.org/pod/Module::Build)
  and [`Module::Install`](https://metacpan.org/pod/Module::Install)
  * On Ubuntu systems, these can easily be installed with:
    ```shell
    apt install libmodule-build-perl libmodule-install-perl
    ```

## Build Instructions
* Clone the [_infrastructure-agent_](https://github.com/ITRS-Group/infrastructure-agent) and
  [_infrastructure-agent-linux-plugins_](https://github.com/ITRS-Group/infrastructure-agent-linux-plugins)
  GitHub repositories.
  ```shell
  git clone https://github.com/ITRS-Group/infrastructure-agent.git
  git clone https://github.com/ITRS-Group/infrastructure-agent-linux-plugins.git
  ```
* Enter the infrastructure-agent repository and create a symlink to 'infrastructure-agent-linux-plugins'
  ```shell
  cd infrastructure-agent
  ln -s ../infrastructure-agent-linux-plugins .
  ```
* Locate the path of the Python 3.9 binary.
  * On most systems this is likely to be under `/usr/bin` but this will vary
* Run the compilation command, passing in the path of your Python binary
```shell
# Note: 'sudo' is needed to compile plugins from monitoring-plugins
sudo make clean tar PYTHON=/usr/bin/python3.9
```
* The compiled agent can be found at `infrastructure-agent.tar.gz`.

## Installation
* Copy the compiled tarball to the target machine and extract it to the desired installation directory.
  In this example, the default location of `/opt/itrs/infrastructure-agent` is used:
```shell
# On the target machine, running as the sudo user
mkdir /opt/itrs
tar -xf infrastructure-agent.tar.gz -C /opt/itrs/
```
* Validate that the agent works by calling the executable directly. Note that it should error out due to configuration issues.
```shell
/opt/itrs/infrastructure-agent/bin/infrastructure-agent
```
* Set up the `systemd` service.
```shell
cp /opt/itrs/infrastructure-agent/installer/infrastructure-agent.service /etc/systemd/system/infrastructure-agent.service
/bin/systemctl enable infrastructure-agent
/bin/systemctl restart infrastructure-agent
```
* Follow the steps on [Installation and Configuration](https://docs.itrsgroup.com/docs/opsview/current/install/opsview-infrastructure-agent-beta-installation/index.html#installation)
  in the Opsview Knowledge Center to finish configuring your agent.
* Validate the Agent is operational.
```shell
/bin/systemctl status infrastructure-agent
```
