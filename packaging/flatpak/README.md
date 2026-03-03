# `re.fossplant.vmlinux-to-elf`

This folder contains a Flatpak template for the https://github.com/marin-m/vmlinux-to-elf GUI

## Local build instructions

## Build instructions

Build dependencies:

```
sudo apt install flatpak-builder flatpak build-essential \
    libgirepository-2.0-dev libgtk-4-dev libadwaita-1-dev \
    gir1.2-adw-1 gir1.2-gtk-4.0 python3-dev python3-pip \
    glib-compile-resources intltool appstream git
sudo snap install --classic astral-uv
```

Then, run:

```
./build.sh
```

## Utilities

These command will generate a `python3-modules.json` file that can serve as a template for specifying the dependencies into `re.fossplant.vmlinux-to-elf.json`:

```bash
cd
git clone git@github.com:flatpak/flatpak-builder-tools.git
git clone git@github.com:marin-m/vmlinux-to-elf.git vte

cd flatpak-builder-tools/pip
uv sync --all-groups --frozen
source .venv/bin/activate

cd ~/vte/packaging/flatpak
~/flatpak-builder-tools/pip/flatpak-pip-generator --pyproject-file ~/vte/pyproject.toml --optdep-groups gui
```

Note: add `--use-deprecated=legacy-resolver` to the `pip3 install` command for the `lz4` module in order to bypass the `Inconsistent version: filename has '4.4.5', but metadata has '0.0.0'` error