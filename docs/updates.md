# Update channels and version control

This document is the endpoint side of controlling which version of Osprey runs on a managed machine. The server side,
which packages builds and decides which build each channel offers, lives with the backend in `OspreyProxy` at
`docs/updates.md`. Read this to understand how a managed browser is pointed at that server.

## Where the extension gets updates

The published build carries an `update_url` in `manifest.json` that points at the public web store. That is correct for
users who install Osprey themselves, because the store keeps them current on the browser's own schedule.

A managed, force-installed deployment does not use that field. When an administrator force-installs the extension, the
update URL comes from the browser's force-install policy value, not from the `update_url` inside the extension. The
policy value is the extension id and the update URL joined by a semicolon. This is the hook an MSP uses to move update
control to its own infrastructure without changing the shipped extension. The public build keeps its store `update_url`,
and managed endpoints override it through policy.

## Pointing an endpoint at a self-hosted update server

On Chrome and Edge, and on the Chromium-based Brave and Vivaldi, the force-install list is `ExtensionInstallForcelist`.
Each entry is one string that names the extension id and the channel manifest URL served by the self-hosted update
server.

```
aaaabbbbccccddddeeeeffffgggghhhh;https://updates.example.com/updates/stable.xml
```

The part before the semicolon is the extension id, which stays constant as long as the operator signs every build with
the same key. The part after it is the channel manifest URL. Assigning a group of endpoints to a channel is done by
giving that group the matching channel URL, so a beta group points at `/updates/beta.xml` while everyone else points at
`/updates/stable.xml`.

## Channels, pinning, and rollback in one line each

The behavior these produce is defined entirely on the server, and this is only how an endpoint experiences them. An
endpoint on a channel receives whatever version that channel currently offers. An endpoint on a pinned channel stays on
one exact version until the operator moves the pin. An endpoint that took a bad build receives the operator's rollback
build, which is the good code republished under a higher version, as an ordinary update on its next poll.

## Preventing removal

Stopping a user from removing or disabling the extension is a browser-level control, set through the same force-install
policy, and it is not something the extension itself enforces. Configure it as part of the deployment. The cross-browser
deployment templates and the managed storage path for each browser are documented on the Osprey site's deployment page.

## The rest of the mechanism

Packaging a CRX, authoring the release catalog and channel configuration, staging a beta, pinning a client, rolling
back, and subscribing to the release feed are all covered in `OspreyProxy/docs/updates.md`. Firefox uses a different
signing and update model and is covered there as well.
