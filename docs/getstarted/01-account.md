# Logging in

Most useful features of this library require an active login session with Apple in order to work correctly.
The reason for this is that the remote endpoints require authentication to actually retrieve data.
This page will guide you through the steps needed to log into an Apple account using FindMy.py.

## Step 0: Account Requirements

FindMy.py requires an **active** Apple Account which has had a device attached to it **at least once**.
It is OK if there are currently no devices signed into the account, as long as a device has signed into
it at least once in the past. Note that this does not have to be a _real_ device: a hackintosh using e.g.
[Docker-OSX](https://github.com/sickcodes/Docker-OSX) may also work for you if the VM is configured correctly.
We do not and will not provide support regarding setting this up.

Additionally, if you want to track your AirTags, iDevices or other FindMy-compatible 3rd party devices,
the account used for FindMy.py does _not_ have to be the same one as the one that the devices are attached to.
Given the right decryption keys, any Apple account can query the location history of any FindMy device.
However, if you want to track such an official device, you currently must have access to a machine that is
running a compatible version of MacOS in order to extract the decryption keys (see later sections).

## Step 1: Creating an AppleAccount instance

The first time we want to sign in, we must manually construct an instance of the [AppleAccount](#findmy.AppleAccount)
class. Creating such a class requires specifying an [Anisette](../technical/15-Anisette.md) provider. Anisette
data is usually generated on-device, and identifies our virtual device when we make a request to Apple's servers.

There are two different Anisette providers included in FindMy.py: [LocalAnisetteProvider](#findmy.LocalAnisetteProvider)
and [RemoteAnisetteProvider](#findmy.RemoteAnisetteProvider). The local provider is much easier to use,
so we will be utilizing it in this example.

```python
from findmy import AppleAccount, LocalAnisetteProvider

ani = LocalAnisetteProvider(libs_path="ani_libs.bin")
account = AppleAccount(ani)
```

Note the `libs_path` argument: the local Anisette provider needs to use some proprietary libraries
from Apple, which will be stored in this file. They will be automatically downloaded if the file is missing.
While the argument is technically optional, it is highly recommended to provide it; otherwise, the library
will need to re-download the bundle every time. The size of the bundle is approximately 2,1 MB.

## Step 2: Logging in

Logging into an Apple Account is an interactive process: depending on the circumstances, 2FA may or may
not be required, and there are multiple different methods to perform 2FA authentication. FindMy.py supports
both SMS and Trusted Device challenges to pass the 2FA check, but you must handle the sign-in flow manually in your application.

```{attention}
FindMy.py currently does not support passkey authentication: [#159](https://github.com/malmeloo/FindMy.py/issues/159).
If you use a passkey to secure your Apple Account, you must disable it to use FindMy.py. This is because enabling
passkeys for your account will disable other 2FA mechanisms.
```

To start the authentication process, provide your email and password as follows:

```python
state = account.login(email, password)
```

The `state` variable will now contain a [LoginState](#findmy.LoginState). If `value == LoginState.LOGGED_IN`, you're
good! Continue to the next step. If `value == LoginState.REQUIRE_2FA`, we need to pass a 2FA challenge first.
Read on to learn how to do this.

In order to pass the 2FA challenge, we first need to find out which challenges Apple provides to us. We can use either
one of these challenges to continue the login flow.

```python
from findmy import LoginState, TrustedDeviceSecondFactorMethod, SmsSecondFactorMethod

if state == LoginState.REQUIRE_2FA:  # Account requires 2FA
    methods = account.get_2fa_methods()

    for i, method in enumerate(methods):
        if isinstance(method, TrustedDeviceSecondFactorMethod):
            print(f"{i} - Trusted Device")
        elif isinstance(method, SmsSecondFactorMethod):
            print(f"{i} - SMS ({method.phone_number})")

    # example output:
    # 0 - Trusted Device
    # 1 - SMS (+31 •• ••••••55)
    # 2 - SMS (+31 •• ••••••32)
```

Depending on your account configuration, you will either get more or fewer 2FA challenge options.
In order to pass one of these challenges, we will first call its `request()` method to request a code
(on a Trusted Device or via SMS), and then use the `submit()` method to submit the code and pass the challenge.

```python
    ind = int(input("Method? > "))

    method = methods[ind]
    method.request()
    code = input("Code? > ")

    method.submit(code)
```

If all went well, you should now be logged in!

## Step 3: Saving / restoring the session

Before we continue to fetching device locations, I first want to talk about properly closing and restoring sessions.
Apple Account sessions are precious, and you shall not create more of them than necessary. Each time we go through the
steps outlined above, a new 'device' is added to your account, and you will need to go through the 2FA flow again.
This is inefficient and simply unnecessary.

Therefore, once you are done, it is good practice to save the current state of the account to a file, as well as close
any resources that the instance may be holding onto:

```python
acc.to_json("account.json")

acc.close()
```

Then, if you want to pick up the session again later:

```python
acc = AppleAccount.from_json("account.json", anisette_libs_path="ani_libs.bin")
```
