<div align="center">
  <img alt="FindMy.py Logo" src="assets/icon.png" width="500">
  <h1>FindMy.py</h1>
</div>

<div align="center">

  _Query Apple's FindMy network with Python!_

  <h5>
      <a href="https://docs.mikealmel.ooo/FindMy.py">
        Docs
      </a>
      <span> | </span>
      <a href="examples/">
        Examples
      </a>
      <span> | </span>
      <a href="https://pypi.org/project/FindMy/">
        PyPI
      </a>
</div>

## 🚀 Overview
The current "Find My-scene" is quite fragmented, with code
being all over the place across multiple repositories,
written by [several authors](#Credits). This project aims to
unify this scene, providing common building blocks for any
application wishing to integrate with the Find My network.

> [!IMPORTANT]
> This project is currently in Alpha. While existing functionality
> will likely not change much, the API design is subject to change
> without prior warning.
> 
> You are encouraged to report any issues you can find on the
> [issue tracker](https://github.com/malmeloo/FindMy.py/issues/)!

## 🧪 Features

- [x] Cross-platform: no Mac needed
- [x] Fetch and decrypt location reports
  - [x] Official accessories (AirTags, iDevices, etc.)
  - [x] Custom AirTags (OpenHaystack) 
- [x] Apple account sign-in
  - [x] SMS 2FA support
  - [x] Trusted Device 2FA support
- [x] Scan for nearby FindMy-devices
  - [x] Decode their info, such as public keys and status bytes
- [x] Import or create your own accessory keys
- [x] Both async and sync APIs

## 📥 Installation

The package can be installed from [PyPi](https://pypi.org/project/findmy/):

```shell
pip install findmy
```

For usage examples, see the [examples](examples) directory.
We are also building out a CLI. Try `python -m findmy` to see the current state of it.
Documentation can be found [here](http://docs.mikealmel.ooo/FindMy.py/).

## 🤝 Contributing

Want to contribute code? That's great! For new features, please open an
[issue](https://github.com/malmeloo/FindMy.py/issues) first so we can discuss.

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.
Before opening a pull request, please ensure that your code adheres to these rules.
There are pre-commit hooks included to help you with this, which you can set up as follows:

```shell
pip install uv
uv sync  # this installs ruff & pre-commit into your environment
pre-commit install
```

After following the above steps, your code will be linted and formatted automatically
before committing it.

## 🧠 Derivative projects

There are several other cool projects based on this library! Some of them have been listed below, make sure to check them out as well.

* [OfflineFindRecovery](https://github.com/hajekj/OfflineFindRecovery) - Set of scripts to precisely locate your lost MacBook.
* [SwiftFindMy](https://github.com/airy10/SwiftFindMy) - Swift port of FindMy.py.
* [FindMy Home Assistant (1)](https://github.com/malmeloo/hass-FindMy) - Home Assistant integration made by the author of FindMy.py.
* [FindMy Home Assistant (2)](github.com/krmax44/homeassistant-findmy) - Home Assistant integration made by [krmax44](https://github.com/krmax44).
* [OpenTagViewer](https://github.com/parawanderer/OpenTagViewer) - Android App to locate your AirTags.
* [Find My Dad](https://github.com/NickCrews/findmydad) - Geofencing application for AirTags using Google Sheets and SMS.

## 🏅 Credits

While I designed the library, the vast majority of actual functionality
is made possible by the following wonderful people and organizations:

- @seemo-lab for [OpenHaystack](https://github.com/seemoo-lab/openhaystack/)
  and their [research](https://doi.org/10.2478/popets-2021-0045);
- @JJTech0130 for [Pypush](https://github.com/JJTech0130/pypush), providing the breakthrough necessary
  for getting this to work without a Mac;
- @biemster for [FindMy](https://github.com/biemster/FindMy), which is the main basis of this project;
- @Dadoum for [pyprovision](https://github.com/Dadoum/pyprovision/) and
  [anisette-v3-server](https://github.com/Dadoum/anisette-v3-server);
- @nythepegasus for [GrandSlam](https://github.com/nythepegasus/grandslam/) SMS 2FA;
- And probably more, so let me know! :D
