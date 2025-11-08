# Related Projects

FindMy.py is not the only project that's active in the Find My scene, nor is it the first.
This page serves as a showcase of all the amazing projects that people are working on.

Projects are grouped by category and ordered by date of insertion.
Projects with a snake emoji (🐍) prepended to their name are either using or based on FindMy.py.
Want to add your own project to the list?
Create an issue, PR or shoot me a message on [Discord](https://discord.gg/EF6UCG2TF6).

## Research / Proof of Concepts

#### [OpenHaystack](https://github.com/seemoo-lab/openhaystack/)

_Author: [seemo-lab](https://github.com/seemo-lab)_

The original FindMy project that started it all. Seemo-lab originally used an Apple Mail plug-in to
obtain the authentication tokens necessary to request device locations.

OpenHaystack also includes scripts and firmware to turn devices such as the Micro:Bit and
generic Linux devices into DIY AirTags.

#### [FindMy](https://github.com/biemster/FindMy/)

_Author: [biemster](https://github.com/biemster)_

After [JJTech](https://github.com/JJTech0130/) discovered how to obtain the authentication tokens
without using a Mac, biemster published his "FindMy" project. It was one of the first scripts that was
able to query locations for DIY AirTags without needing access to a Mac.

Fun fact: FindMy.py originally started as an adoptation of biemster's FindMy, but refactored as a Python library.
Since then, FindMy.py has deviated from biemster's project somewhat. FindMy.py solely focuses on querying device locations
and has added support for local Bluetooth scanning and official AirTags, while biemster's FindMy mainly focuses on
DIY tags, and includes firmware for some embedded devices to turn them into AirTags.

## Location Tracking

#### 🐍 [hass-FindMy](https://github.com/malmeloo/hass-FindMy)

_Author: [malmeloo](https://github.com/malmeloo/)_

Home Assistant integration made by the author of FindMy.py that allows you to track your devices as device tracker entities.
FindMy.py is continuously updated to ensure compatibility with Home Assistant's requirements and to minimize breakage
due to dependency conflicts.

#### 🐍 [OfflineFindRecovery](https://github.com/hajekj/OfflineFindRecovery)

_Author: [hajekj](https://github.com/hajekj/)_

Set of scripts meant to precisely locate a lost MacBook.

#### 🐍 [homeassistant-FindMy](https://github.com/krmax44/homeassistant-findmy)

_Author: [krmax44](https://github.com/krmax44/)_

Home Assistant integration to track your FindMy devices.

#### 🐍 [OpenTagViewer](https://github.com/parawanderer/OpenTagViewer)

_Author: [parawanderer](https://github.com/parawanderer/)_

Android app that allows you to track your FindMy devices.

#### 🐍 [Find My Dad](https://github.com/NickCrews/findmydad)

_Author: [NickCrews](https://github.com/NickCrews/)_

Geofencing application for AirTags using Google Sheets and SMS.

#### 🐍 [FindMy-Dashboard](https://github.com/Philip2809/FindMy-Dashboard)

_Author: [Philip2809](https://github.com/Philip2809/)_

Web dashboard to view the location of your FindMy devices on a map.

#### 🐍 [LockMyTag](https://github.com/pablobuenaposada/LockMyTag)

_Author: [pablobuenaposada](https://github.com/pablobuenaposada/)_

Geofencing for FindMy devices. Also includes a map to view device locations.

#### 🐍 [AirTrack](https://gitlab.com/franga2000/airtrack)

_Author: [franga2000](https://github.com/pablobuenaposada/)_

Basic web UI for AirTags and other MFI trackers.

#### 🐍 [Simply-Haystack](https://github.com/alyxdeburca/simply-haystack/)

_Author: [alyxdeburca](https://github.com/alyxdeburca/)_

Web interface to track your FindMy devices.

## Libraries

#### 🐍 [SwiftFindMy](https://github.com/airy10/SwiftFindMy)

_Author: [Airy10](https://github.com/airy10/)_

Swift port of FindMy.py
