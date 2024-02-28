# Makefile for ITRS Group infrastructure-agent
# Copyright (C) 2003-2024 ITRS Group Ltd. All rights reserved

VENV ?= venv
BASE_DIR ?= infrastructure-agent
AGENT_DIR ?= /opt/itrs/infrastructure-agent
BUILD_EXE_DIR ?= $(BASE_DIR)/bin
INSTALLER_DIR ?= $(BASE_DIR)/installer
PLUGIN_INSTALL_DIR ?= $(BASE_DIR)/plugins
CFG_DIR ?= $(BASE_DIR)/cfg
CFG_CUSTOM_DIR ?= $(BASE_DIR)/cfg/custom
CFG ?= $(CFG_DIR)/agent.default.yml
VAR_DIR ?= $(BASE_DIR)/var
TAR_FILE ?= infrastructure-agent.tar.gz
AGENT_SERVICE_FILE ?= infrastructure-agent.service

PYTHON ?= $(shell which python3)
ifdef PYTHON
PYTHON_MAJOR_VERSION = $(shell $(PYTHON) -c 'import sys; print(sys.version_info.major)')
PYTHON_MINOR_VERSION = $(shell $(PYTHON) -c 'import sys; print(sys.version_info.minor)')
PYTHON_PRETTY_VERSION = $(PYTHON_MAJOR_VERSION).$(PYTHON_MINOR_VERSION)
PLATFORM = $(shell $(PYTHON) -c 'import platform; print(platform.system().lower())')
PLUGIN_DIR = infrastructure-agent-$(PLATFORM)-plugins
endif

TEST_CERTS = tests/resources/certs

# Versions of Python we support (Python 3.x)
SUPPORTED_PYTHON_MAJOR_VERSION = 3
SUPPORTED_PYTHON_MINOR_VERSIONS_MIN := 9
SUPPORTED_PYTHON_MINOR_VERSIONS_MAX := 9

check_python_version:
ifndef PYTHON
	$(error Python 3 executable cannot be found, please set the PYTHON environment variable)
else

ifneq ($(PYTHON_MAJOR_VERSION), $(SUPPORTED_PYTHON_MAJOR_VERSION))
	$(error 'PYTHON' environment variable must point to a Python $(SUPPORTED_PYTHON_MAJOR_VERSION).x executable, not Python $(PYTHON_PRETTY_VERSION))
endif

ifeq ($(shell test $(PYTHON_MINOR_VERSION) -lt $(SUPPORTED_PYTHON_MINOR_VERSIONS_MIN); echo $$?), 0)
	$(error "'PYTHON' environment variable points to a $(PYTHON_PRETTY_VERSION) executable. This is below the minimum supported version of $(SUPPORTED_PYTHON_MAJOR_VERSION).$(SUPPORTED_PYTHON_MINOR_VERSIONS_MIN)")
endif

ifeq ($(shell test $(PYTHON_MINOR_VERSION) -gt $(SUPPORTED_PYTHON_MINOR_VERSIONS_MAX); echo $$?), 0)
	$(warning "'PYTHON' environment variable points to a $(PYTHON_PRETTY_VERSION) executable. This is above the recommended maximum of $(SUPPORTED_PYTHON_MAJOR_VERSION).$(SUPPORTED_PYTHON_MINOR_VERSIONS_MAX)")
endif
endif

all:

lint:
	@# Check source code syntax
	flake8

$(TEST_CERTS):
	@# Create a certificate for the tests
	mkdir $@
	openssl req \
		-x509 \
		-newkey rsa:4096 \
		-keyout $@/key.pem \
		-out $@/cert.pem \
		-sha256 \
		-days 1 \
		-subj '/CN=test.system' \
		-nodes

test: check_python_version $(TEST_CERTS)
	@# Run unit tests using tox
	export PYTHONPATH=$(PYTHONPATH) && \
	export VIRTUALENV_EXTRA_SEARCH_DIR=$(VIRTUALENV_EXTRA_SEARCH_DIR) && \
	export VIRTUALENV_SEEDER=$(VIRTUALENV_SEEDER) && \
	tox

$(VENV): check_python_version
	@# Create virtual environment for the build
	$(PYTHON) -m venv $@
	. $(VENV)/bin/activate && pip install -r requirements.txt -c constraints.txt

$(AGENT_SERVICE_FILE):
	AGENT_BIN_PATH=$(AGENT_DIR)/bin/infrastructure-agent envsubst < $@.in > $@

ifneq ("$(wildcard $(PLUGIN_DIR))", "")
$(CFG): BUILD_CONFIG_ARGS=--install-dir $(AGENT_DIR) --plugin-config-dir $(PLUGIN_DIR)/config
else
$(CFG): BUILD_CONFIG_ARGS=--install-dir $(AGENT_DIR)
endif
$(CFG): $(VENV)
	@# Generate the default configuration
	$(VENV)/bin/python build_config.py $(BUILD_CONFIG_ARGS)
	mkdir -p $(CFG_DIR)
	mkdir -p $(CFG_CUSTOM_DIR)
	mv cfg/`basename $(CFG)` $(CFG_DIR)

$(VAR_DIR):
	@# Create var dir for certs
	mkdir -p $(VAR_DIR)

plugins:
	mkdir -p $(PLUGIN_INSTALL_DIR)
ifneq ("$(wildcard $(PLUGIN_DIR))", "")
	$(MAKE) -C $(PLUGIN_DIR) build DESTDIR=""
else
	@echo "Skipping Plugin compilation, '$(PLUGIN_DIR)' not found"
endif

agent:
	@# Build the infrastructure agent
	mkdir -p $(BUILD_EXE_DIR) $(INSTALLER_DIR)
	. $(VENV)/bin/activate && python setup.py build --build-exe $(BUILD_EXE_DIR)

build: agent plugins $(AGENT_SERVICE_FILE) $(CFG) $(VAR_DIR)
	cp $(AGENT_SERVICE_FILE) $(INSTALLER_DIR)
	cp -rv $(PLUGIN_DIR)/out/perl $(PLUGIN_DIR)/out/plugins/* $(PLUGIN_INSTALL_DIR)

tar: $(VENV) build
	@# Generate the tar file
	tar -cvzf $(TAR_FILE) $(BASE_DIR)

clean:
	@# Remove temporary files
	$(RM) -r .coverage htmlcov junit.xml .tox
	$(RM) -r $(AGENT_SERVICE_FILE)
	$(RM) -r $(BUILD_EXE_DIR)
	$(RM) -r $(CFG_DIR) $(CFG_CUSTOM_DIR)
	$(RM) -r $(VAR_DIR)
	$(RM) -r $(VENV)
	$(RM) -r $(TEST_CERTS)
ifneq ("$(wildcard $(PLUGIN_DIR))", "")
	$(MAKE) -C $(PLUGIN_DIR) clean
endif

.PHONY: all lint test agent build install plugins clean tar check_python_version
