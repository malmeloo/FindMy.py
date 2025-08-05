# Intercepting Network Requests

A big part of our understanding of how the FindMy network functions originates from
network captures detailing how official apps query location reports.
This page aims to provide a quickstart on setting up an environment in which you can
freely inspect network requests made the FindMy app on a Mac.

```{note}
This guide has only been tested on Sonoma, but it will likely work on other
versions of MacOS as well.
```

## Disabling SSL pinning

Applications on MacOS implement SSL pinning by default. This means that Apple can determine which server-side
certificates are allowed to be used when an application makes a network request. This presents a problem
when we want to inspect these requests: typically, to inspect encrypted traffic using a proxy, we need to perform
a Man-In-The-Middle (MITM) attack on ourselves in order to 'swap out' the certificate with one that we have the private key of.
This is not possible while SSL pinning is active, because the application will simply reject our certificate.

For this reason, we will first need to disable SSL pinning. We will do this by utilizing [Frida](https://frida.re/)
to attach to the processes that we want to inspect, and then using a script to bypass SSL pinning.

Start off by downloading [this JavaScript file](https://gist.github.com/azenla/37f941de24c5dfe46f3b8e93d94ce909) and saving
it to a location where you can easily find it again.

Next, let's actually install Frida by running the following command:

```bash
pip install frida-tools==13.7.1
```

```{hint}
The above command installs an older version of Frida that is compatible with the script we are going to use.
If you need to use a newer version for whatever reason, you need to apply [these fixes](https://gist.github.com/azenla/37f941de24c5dfe46f3b8e93d94ce909?permalink_comment_id=5675248#gistcomment-5675248)
to the script we downloaded before continuing.

Note that I will not be able to provide support if you use a version other than the one suggested above.
```

To inspect network requests for FindMy, we want to attach Frida to the `searchpartyuseragent` daemon.
Open a terminal and enter the following command, substituting the path to the script if necessary:

```bash
frida -l disable-ssl-pin.js searchpartyuseragent
```

```{important}
If the above command does not work, you may need to temporarily disable [System Integrity Protection](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection).
Make sure to re-enable it once you're done intercepting!
```

If all went well, Frida should now be running. Keep the terminal open while capturing network requests.

## Intercepting requests

If you're already familiar with MITM proxies, you can probably skip this step; just use your favorite proxy
while Frida is running. If you're not, read on.

We will be using [mitmproxy](https://www.mitmproxy.org/) in order to intercept network requests. Install it before continuing:

```bash
brew install --cask mitmproxy
```

Mitmproxy supports several methods to intercept local traffic. We will be using `Local Capture` mode, as it's the easiest to set up
and tear down afterwards. Run the following command to start the proxy:

```bash
mitmweb --mode local
```

```{tip}
Mitmproxy / MacOS may bug you about enabling the correct profile in system settings. If it does, simply do what it says
and come back here.
```

```{tip}
Applications other than FindMy may lose their network connection while the capture is running. Simply stop mitmproxy
once you're done and it will go back to normal.
```

If all went well, your browser should open the mitmweb interface. From here, you will see all network requests being made
by `searchpartyuseragent`, as well as their responses.
