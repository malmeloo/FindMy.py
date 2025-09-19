# Fetching device locations

```{note}
The steps below assume that you have already obtained an `AppleAccount` instance with a login session attached.
If you don't have this yet, follow the instructions [here](01-account.md) to obtain one.
```

## Step 1: Obtaining device information

In order to fetch location reports for your device, FindMy.py requires the keys that are used to encrypt the location
reports that are uploaded by other Apple devices. Depending on the device you are using, this process can differ somewhat.

```{tip}
This step can be quite annoying, but don't fret! You only have to do this once for each device you want to track.
Can't figure it out? Join the [Discord server](http://discord.gg/EF6UCG2TF6) and we'll try to help!
```

```````{tab-set}
:sync-group: device-type

``````{tab-item} Official device
:sync: official-device

If you want to track an official FindMy device (AirTag, iPhone/iPad/Mac, 3rd party 'works with FindMy'), you currently
need access to a device running MacOS. This can be either a real device or a Hackintosh, however, make sure that you are
signed into your Apple account and that the FindMy app is able to track your device. This is a one-time process, so you
can also ask a friend to borrow their Mac.

Note that not all versions of MacOS are currently supported. Please see the menus below for more details.

`````{tab-set}

````{tab-item} MacOS <= 14
FindMy.py includes a built-in utility that will dump the accessories from your Mac. Note that it will pop up
an interactive password prompt to unlock the keychain; therefore, this utility does **not** work over SSH.

```bash
python3 -m findmy decrypt --out-dir devices/
```

The above command will write one JSON file for each accessory found on your system to the `devices` directory.
These files are ready to be used with FindMy.py!

````

````{tab-item} MacOS 15
MacOS 15 may or may not include additional protection for the BeaconStoreKey. You should first try to follow
the instructions for MacOS 14. If these do not work for you, read on.

If the instructions for MacOS 14 do not work for you, the BeaconStoreKey is likely protected. We will need to
use an additional utility to decrypt a set of 'plist' files. Go and follow the instructions at @pajowu's
[beaconstorekey-extractor](https://github.com/pajowu/beaconstorekey-extractor), then return here.

Welcome back! **Did you remember to re-enable System Integrity Protection? If not, go do that now!**

If all went well, you should now have one or multiple decrypted plist files. Hooray!
That was the most difficult part. These plist files are not directly compatible with FindMy.py,
so we'll need to convert them first.
Save this [plist_to_json](https://github.com/malmeloo/FindMy.py/blob/main/examples/plist_to_json.py)
script somewhere on your computer and run it as follows:

```python
python3 plist_to_json.py path/to/original_file.plist device.json
```

This will convert a single plist file into a FindMy.py-compatible JSON file and save it to `device.json`.
Repeat this step for any other plist files you want to convert.

```{note}
The first time you try to fetch the location of your device, FindMy.py might appear to hang for a bit.
This is because the beaconstorekey-extractor tool does not export key alignment data, so FindMy.py needs
to query a wide range of possible values to find the right alignment to use. The older your tag is, the
longer it will take to do this process.

If you are physically close to the tag, you can speed this up significantly by using the
[Tag Scanner](https://github.com/malmeloo/FindMy.py/blob/main/examples/scanner.py). This will attempt
to discover your tag via Bluetooth and update its alignment based on the values that it is currently broadcasting.
Make sure to give it your device JSON file as argument! Otherwise, the scanner does not know which tag
to look for.
```

````

````{tab-item} MacOS 26
MacOS 26 appears to protect the BeaconStoreKey needed to decrypt the plist records that contain accessory data.
Unlike with MacOS 15, disabling SIP does not appear to fix it.

If you figure out a way to dump the plist encryption key, please share your findings
[here](https://github.com/malmeloo/FindMy.py/issues/177).
````

````{tab-item} I don't have a Mac :(
Unfortunately, FindMy.py currently only supports dumping accessory information from a Mac.
Device encryption keys are stored in your account's keychain, which is only accessible on Apple hardware.
iOS / iPadOS is too limited and does not allow us to access the necessary device secrets.

A method to join the encrypted keychain circle from non-MacOS hardware has recently been found,
but it takes a lot of time and effort to implement. We are currently considering what the best
way would be to implement this, however, we are not currently actively working on making this happen.
You can follow development on this feature and voice your support in
[this](https://github.com/malmeloo/FindMy.py/issues/173) GitHub issue.
````

`````

``````

``````{tab-item} Custom device
:sync: custom-device

If you built your own FindMy tag (using e.g. [OpenHaystack](https://https://github.com/seemoo-lab/openhaystack),
[macless-haystack](https://github.com/dchristl/macless-haystack), or [one](https://github.com/pix/heystack-nrf5x)
of the [many](https://github.com/hybridgroup/go-haystack) other [available](https://github.com/dakhnod/FakeTag)
projects), it will most likely be broadcasting a static key. In this case, grab the private key that you generated
and create a [KeyPair](#findmy.KeyPair) object as follows:

````python
# PRIVATE key in base64 format
device = KeyPair.from_b64(...)
````

`````{admonition} Don't have a private key yet?
:class: tip dropdown

If you are setting up your DIY tag and have not generated a private key yet, you can use FindMy.py to do it!

````python
device = KeyPair.new()
print(device.private_key_b64)
# a6C9bgy4H/bpZ7vGtVBdO3/UyNjan2/3a7UW4w==
````

`````

``````

```````

## Step 2: Testing your device JSON file (optional)

At this point, you should be able to fetch location reports for your accessory. FindMy.py includes extensive
example scripts to help you test this.

`````{tab-set}
:sync-group: device-type

````{tab-item} Official device
:sync: official-device

Clone the FindMy.py repository somewhere and enter the `examples/` directory.
Then run the following command:

```bash
python3 airtag.py path_to_device.json
```

The script will ask for your account credentials. If all went well, it will output a location report as follows:

```
Last known location:
 - LocationReport(hashed_adv_key=..., timestamp=..., lat=..., lon=...)
```

````

````{tab-item} Custom device
:sync: custom-device

Clone the FindMy.py repository somewhere and enter the `examples/` directory.
Then run the following command:

```bash
python3 fetch_reports.py <private_key_base64>
```

The script will ask for your account credentials. If all went well, it will output a location report as follows:

```
Last known location:
 - LocationReport(hashed_adv_key=..., timestamp=..., lat=..., lon=...)
```

````

`````

## Step 3: Fetching location reports

To fetch location report for a device, you can use the [fetch_location](#findmy.AppleAccount.fetch_location) method
on your [AppleAccount](#findmy.AppleAccount) instance. This method will return either a [LocationReport](#findmy.LocationReport)
if a location is found, or `None` if no location was found.

```python
location = account.fetch_location(device)
print(location)

# LocationReport(...)
```

If you want to query locations for multiple devices, you can also pass in a list. FindMy.py will then optimize its
request payloads to get the locations in as few queries to Apple servers as possible. In this case, the method will
return a dictionary with the given devices as keys, and the fetch result as value.

```python
locations = account.fetch_location([device1, device2])
print(locations)

# {device1: LocationReport(...), device2: None}
```

You can also save location reports to JSON if you want to store them:

```python
location.to_json("report.json")
```

````{caution}
The JSON representation of a location report includes the device's encryption key at that time.
**Sharing this file with someone else will allow them to query location reports for your device.**
You can avoid including the key by setting the `include_key` parameter to `False`, however,
this will save the report in its encrypted format, which means you will have to manually decrypt it again.

```python
enc_report_json = report.to_json(include_key=False)
report = LocationReport.from_json(enc_report_json)

print(report.is_decrypted)
# False

print(report.latitude)
# RuntimeError: Latitude is unavailable while the report is encrypted.

report.decrypt(key) # key is the `KeyPair` of the device at that time

print(report.is_decrypted)
# True
```

````

## Step 4: Saving accessory state to disk

After fetching, FindMy.py may have made changes to the accessory's internal state.
Saving these changes to the accessory's JSON representation ensures that the process of fetching
the device's location will be as fast and efficient as possible.

The device's state can be exported to JSON as follows:

```python
device.to_json("airtag.json")
```

```{tip}
As you may have noticed, many objects in FindMy.py can be (de)serialized to and from JSON.
Classes such as [AppleAccount](#findmy.AppleAccount), [LocationReport](#findmy.LocationReport),
[KeyPair](#findmy.KeyPair) and [FindMyAccessory](#findmy.FindMyAccessory) all subclass
[Serializable](#findmy.util.abc.Serializable). Whenever a class in FindMy.py subclasses `Serializable`,
you can save and load its state using the `to_json` and `from_json` methods.
```
