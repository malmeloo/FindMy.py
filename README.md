# FindMy.py

![](https://img.shields.io/pypi/v/FindMy)
![](https://img.shields.io/github/license/malmeloo/FindMy.py)
![](https://img.shields.io/pypi/pyversions/FindMy)

The all-in-one library that provides everything you need
to query Apple's FindMy network!

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
> [issue tracker](https://github.com/malmeloo/FindMy.py/)!

### Features

- [x] Cross-platform: no Mac needed
- [x] Fetch location reports
  - [x] Apple acount sign-in
  - [x] SMS 2FA support
- [x] Scan for nearby FindMy-devices
  - [x] Decode their info, such as public keys and status bytes
- [x] Import or create your own accessory keys
- [x] Both async and sync APIs

### Roadmap

- [ ] Trusted device 2FA
    - Work has been done, but needs testing (I don't own any Apple devices)
- [ ] Local anisette generation (without server)
    - Can be done using [pyprovision](https://github.com/Dadoum/pyprovision/),
      however I want to wait until Python wheels are available.

## Installation

The package can be installed from [PyPi](https://pypi.org/project/findmy/):

```shell
pip install findmy
```

For usage examples, see the [examples](examples) directory. Documentation coming soon™.

## Contributing

Want to contribute code? That's great! For new features, please open an
[issue](https://github.com/malmeloo/FindMy.py/issues) first so we can discuss.

This project uses [Ruff](https://docs.astral.sh/ruff/) for linting and formatting.
Before opening a pull request, please ensure that your code adheres to these rules.
There are pre-commit hooks included to help you with this, which you can set up as follows:

```shell
pip install poetry ruff
poetry install  # this installs pre-commit into your environment
pre-commit install
```

After following the above steps, your code will be linted and formatted automatically
before committing it.

## Credits

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
