# getting started

## with asdf

### tools needed

- python 3.11
- [hatch](https://hatch.pypa.io/)
- [asdf](https://asdf-vm.com/guide/getting-started.html)

### setup

1. install [asdf](https://asdf-vm.com/guide/getting-started.html)
2. run `asdf install` in this directory to install all needed tools
3. run `just setup` to install the pre-commit hooks etc.

### pre-commit

1. run `just check` to lint the files and auto-format them.
   you can optionally run `just format` and `just lint` as a single action.
2. fix the issues which ruff reports
3. run `just build` to check if it builds correctly
4. commit changes

## manual

### tools needed

- python 3.11
- [hatch](https://hatch.pypa.io/)

### setup

1. install [just](https://github.com/casey/just)
2. run `just setup` to install the pre-commit hooks etc.

### pre-commit

1. run `hatch run lint:fmt` to lint the files and auto-format them.
2. fix the issues which ruff reports
3. run `hatch build --clean` to check if it builds correctly
4. commit changes
