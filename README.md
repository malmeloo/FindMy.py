# FindMy.py

The all-in-one library that provides everything you need
to query Apple's FindMy network!

The current "Find My-scene" is quite fragmented, with code
being all over the place across multiple repositories,
written by [several authors](#Credits). This project aims to
unify this scene, providing common building blocks for any
application wishing to integrate with the Find My network.

## Features

- [x] Works without any Apple devices
- [x] Apple Account log-in
- [x] SMS 2FA support
- [x] Fetch location reports
- [x] Generate new accessory keys
- [x] Import accessory keys
- [x] Fully async
- [x] Modular with a high degree of manual control

## Roadmap

- [ ] Trusted device 2FA
    - Work has been done, but needs testing (I don't own any Apple devices)
- [ ] Local anisette generation (without server)
    - Can be done using [pyprovision](https://github.com/Dadoum/pyprovision/),
      however I want to wait until Python wheels are available.
- [ ] Sync API wrapper
    - I realize not everyone may be comfortable using an async library;
      building a synchronous wrapper around the `AppleAccount` class would be nice.

# Installation

TODO

# Credits

While I designed the library, the vast majority of the actual functionality
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
