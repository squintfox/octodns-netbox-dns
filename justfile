#!/usr/bin/env just --justfile

default: show_receipts

set shell := ["bash", "-uc"]
set dotenv-load

show_receipts:
    @just --list

show_system_info:
    @echo "=================================="
    @echo "os : {{os()}}"
    @echo "arch: {{arch()}}"
    @echo "justfile dir: {{justfile_directory()}}"
    @echo "invocation dir: {{invocation_directory()}}"
    @echo "running dir: `pwd -P`"
    @echo "=================================="

setup:
    @asdf install
    @lefthook install

create_venv:
    @echo "creating venv"
    @python3 -m pip install --upgrade pip setuptools wheel
    @python3 -m venv venv

install_deps:
    @echo "installing dependencies"
    @python3 -m hatch dep show requirements --project-only > /tmp/requirements.txt
    @pip3 install -r /tmp/requirements.txt

install_deps_dev:
    @echo "installing dev dependencies"
    @python3 -m hatch dep show requirements --project-only > /tmp/requirements.txt
    @python3 -m hatch dep show requirements --env-only >> /tmp/requirements.txt
    @pip3 install -r /tmp/requirements.txt

create_reqs:
    @echo "creating requirements"
    @pipreqs --force --savepath requirements.txt src/octodns_netbox_dns

lint:
    just show_system_info
    just test_shfmt
    just test_shfmt
    @hatch run lint:style
    @hatch run lint:typing

format:
    just show_system_info
    just format_shfmt
    @hatch run lint:fmt
