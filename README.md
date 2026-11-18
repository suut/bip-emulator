BIP modem emulator for SGP.32 eUICC testing
------------

The main intent is for testing SGP.32 eUICCs (eSIMs) with an embedded IoT Profile Agent (IPAe). SGP.32 is the IoT counterpart to the usual SGP.22 consumer eSIM standard.

Instead of the terminal equipment scanning an activation QRCode then talking to the operator's server in order to retrieve the profile, a SGP.32 eUICC with IPAe will do that on its own as long as the modem provides the adequate SIMToolkit/Card Application Toolkit/USIM Application Toolkit functionality.

This program emulates a cellular modem using a real SIM card, and provides all the necessary CAT/USAT functions expected by the SIM, including Bearer Independent Protocol channels (TCP/UDP and IPv4/IPVv6) so the SIM can get internet access.

The SIM card under test must be inserted in a smartcard reader and connected to the computer. Any CCID reader should work; ACS ACR39T is a good one if you need a recommendation.

This program uses a TUI (Terminal User Interface). The screen is split in two: the top part is the output log, and the bottom part is the input field for the command-line.

[![Screenshot of the program](/docs/bip-emulator.png)](/docs/bip-emulator.png)

Table of contents:
* [About SGP.32](#about-sgp32)
* [Supported USAT proactive features](#supported-usat-proactive-features)
* [Program startup flow](#program-startup-flow)
* [Command-line arguments](#command-line-arguments)
* [Commands description](#commands-description)

## About SGP.32

SGP.32 is the IoT eSIM version of the consumer SGP.22 eSIM standard.

Within SGP.22 the terminal equipment (i.e. the phone) is running a Local Profile Agent which manages the eSIM profiles as requested by the user, and installs new profiles when the user scans a QRCode or enters an activation code. When the user wants to install a new profile, the LPA is contacting the operator servers (SM-DP) to download the new profiles on behalf of the SIM, then loads the profile into the SIM, and switches to the new profile when requested by the user.

On the other hand SGP.32 is made for IoT and other headless installations. There is a new component called an eIM which is a server that the SIM will connect to in order to know which actions to take (download a profile, switch profiles, change configuration, etc.).

And another innovation (although it was already technically possible with SGP.22 but nobody bothered to implement it) is the IoT Profile Agent (the new name of the LPA) embedded into the SIM itself. Having specific eSIM code in the terminal equipment is not necessary anymore, and the SIM can be managed remotely even if the device has no idea about eSIMs, as long as the modem supports BIP.

Not all SGP.32 eUICCs implement an IPAe (embedded IPA); some of them still require an IPAd (device IPA). Then the flow is similar to SGP.22, except that the IPAd will get its instructions from the eIM instead of from the user.

Theoretically SGP.32 does remove the possibility to locally manage profiles, i.e. being able to directly enable or disable a profile from the local APDU interface. In practice, manufacturers of SGP.32 eUICCs will still support these SGP.22 commands as it is a frequent ask by customers.

This application is made for testing SGP.32 with IPAe, as such it does not implement a full IPAd, it is only able to query the eUICC info, query the list of profiles, and enable or disable profiles.

## Supported USAT proactive features

The following proactive commands are understood by the emulator:
* POLL INTERVAL, to negotiate the interval at which to send a STATUS to the card to poll for proactive commands 
* SET UP EVENT LIST, with the following events being sent when relevant:
  * *Location status* when connecting or disconnecting the network
  * *Network Rejection* when triggered by the user, either immediately or after a profile switch
  * *Data available* when new data arrived on the socket of a BIP channel
  * *Channel status* when the TCP socket of a BIP channel is closed by the remote host
* TIMER MANAGEMENT, with the TIMER EXPIRATION envelope command being sent when a timer expires
  * Start timer
  * Deactivate timer
  * Get current timer value
* PROVIDE LOCAL INFORMATION
  * Code 00 for location information (current operator, current cell tower)
  * Code 01 for the IMEI
* OPEN CHANNEL, to open a BIP channel
* CLOSE CHANNEL, to close an open BIP channel
* WRITE DATA, to write data to the socket of a BIP channel
* READ DATA, to read data from the socket of a BIP channel
* REFRESH
  * Refresh reasons *UICC reset* (04) and *eUICC Profile State Change* (09) both trigger a UICC reset

## Program startup flow

```mermaid
stateDiagram-v2
    [*] --> CardReset
    CardReset --> SendTCaps
    SendTCaps --> SwitchProfile: if requested
    SwitchProfile --> CardReset
    SendTCaps --> ParseSGP2232Info
    ParseSGP2232Info --> EnableIPAe: if SGP.32
    ParseSGP2232Info --> VerifyPIN
    EnableIPAe --> VerifyPIN
    VerifyPIN --> UpdateNetworkLocation
    UpdateNetworkLocation --> SendTerminalProfile
    SendTerminalProfile --> InitializeUSAT
    InitializeUSAT --> SendNetworkRejection: if scheduled
    SendNetworkRejection --> ProcessCardCommands
    InitializeUSAT --> ProcessCardCommands
    ProcessCardCommands --> CardReset: reset requested
    ProcessCardCommands --> ProcessCardCommands: infinite loop
    
    CardReset: card reset
    SendTCaps: send TERMINAL CAPABILITY
    SwitchProfile: manually switch eUICC profile
    ParseSGP2232Info: parse SGP.22 and SGP.32 info
    EnableIPAe: enable SGP.32 IPAe
    VerifyPIN: verify PIN of the active profile
    UpdateNetworkLocation: update the current network location in the USIM files
    SendTerminalProfile: send the USAT terminal profile
    InitializeUSAT: initialize USAT (timers, polling interval, IMEI, ...)
    SendNetworkRejection: send a network rejection event
    ProcessCardCommands: process user commands and SIM card proactive commands
```

## Command-line arguments

* `--mcc`: mobile country code, 3 digits
* `--mnc`: mobile network code, 2 or 3 digits
* `--imei`: IMEI of the simulated mobile equipment
* `-p, --pin`: PIN code of the SIM/profile (warning: on an eUICC the same PIN will be used to unlock all profiles that require a PIN code; disable the PIN code first if that is not what you want)
* `-n, --network`: one of `none`, `2G`, `3G`, `4G`, `5G`; initial network attachment state
* `-r, --reader`: index of the smartcard reader to use, or `list` for a list of readers, or `auto` for auto-selection.
* `--dns-server`: DNS server address to give to the SIM when requested, the default is 8.8.8.8

## Commands description

The commands are:
* [exit](#exit)
* [help](#help)
* [network](#network)
* [profile](#profile)
* [reset](#reset)
* [poll](#poll)

Each command and subcommand can take the `-h` argument in order to print its help text.

### `exit`

This simply exits the program.

### `help`

This prints the list of commands.

### `network`

Manage the cellular network as seen by the SIM.

Subcommands:
* [status](#network-status)
* [connect](#network-connect)
* [disconnect](#network-disconnect)
* [reject](#network-reject)

#### `network status`

This prints the currently attached network, which is one of:
* disconnected
* 2G (GERAN)
* 3G (UTRAN)
* 4G (E-UTRAN)
* 5G (NG-RAN)

The support for the various network types depends on the SIM card and the currently activated profile for an eUICC; not all SIM cards do support 5G for instance.

The operator (MCC and MNC) as well as the currently attached cell is also printed if the network is not disconnected. 

#### `network connect`

This command simulates an attachment to the network after having been disconnected.

#### `network disconnect`

This command simulates a disconnection from the network.

#### `network reject`

This command simulates a network rejection event. It is possible to wait until after a profile change before sending the event.

This is useful for testing either fallback/rollback mechanism of an eUICC:
* Make sure to be connected to the network
* Use the command `network reject --after-profile-state-change`
* Trigger a profile switch from the eIM, granting the rollback mechanism (or not)
* Wait until the profile switch happens, then the network rejection event will be sent
* Observe that the eUICC is falling back to its bootstrap profile (or another profile with the fallback attribute), or to the previous profile if rollback happens

### `profile`

Manage profiles on a SGP.22/SGP.32 eUICC.

Subcommands:
* [list](#profile-list)
* [switch](#profile-switch)

#### `profile list`

List some information about the profiles on the eUICC. The list of profiles is read at reset so it might not be up to date if a new profile was installed on the eUICC since then.

#### `profile switch`

Switch to another profile, given by its ICCID. The target profile must be disabled.

### `reset`

Reset the UICC, which triggers a re-reading of the SGP.22/SGP.32 information and the list of profiles.

A reset will automatically happen if the SIM card requests one, for instance if there was a profile switch triggered by the eIM on a SGP.32 eUICC.

### `poll`

Ask a Thales IPAe to poll for changes (this will cause the IPAe to go contact the eIM soon-ish). This is only for Thales SGP.32 eUICCs and the local APDU polling must be enabled (the Polling local interface setting must be set to `ENABLED_BY_APDU_AND_STK_MENU` or `ENABLED_BY_APDU`).
