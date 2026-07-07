# Osprey: Browser Protection

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Chrome Users](https://img.shields.io/chrome-web-store/users/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd?label=Chrome%20Users&color=00CC00)](https://osprey.ac/chrome)
[![Edge Users](https://img.shields.io/badge/dynamic/json?label=Edge%20Users&color=00CC00&query=%24.activeInstallCount&url=https%3A%2F%2Fmicrosoftedge.microsoft.com%2Faddons%2Fgetproductdetailsbycrxid%2Fnopglhplnghfhpniofkcopmhbjdonlgn)](https://osprey.ac/edge)
[![Firefox Users](https://img.shields.io/amo/users/osprey-browser-protection?label=Firefox%20Users&color=00CC00)](https://osprey.ac/firefox)

**Osprey** is a free, open-source browser security extension that protects you from phishing, malware, scams, and other
malicious websites. As you browse, Osprey checks every site you visit against more than **20 threat-intelligence
providers**, then blocks or warns you the moment one of them flags a site as dangerous.

[Terms of Service](https://osprey.ac/terms)
• [Privacy Policy](https://osprey.ac/privacy)
• [Wiki (FAQs)](https://osprey.ac/wiki)
• [MalwareTips](https://malwaretips.com/threads/osprey-browser-protection-discussion-and-updates.135565/?utm_source=osprey)
• [Wilders Security](https://wilderssecurity.com/threads/osprey-browser-protection.456729/?utm_source=osprey)

###

[![Google Chrome](https://i.imgur.com/R9AN3cA.png)](https://chromewebstore.google.com/detail/osprey-browser-protection/jmnpibhfpmpfjhhkmpadlbgjnbhpjgnd)
[![Microsoft Edge](https://i.imgur.com/oVmDDtj.png)](https://microsoftedge.microsoft.com/addons/detail/osprey-browser-protectio/nopglhplnghfhpniofkcopmhbjdonlgn)
[![Firefox](https://i.imgur.com/uXgho1n.png)](https://addons.mozilla.org/en-US/firefox/addon/osprey-browser-protection)

###

![Osprey Banner](https://i.imgur.com/zzv8QYh.png)

###

## About Osprey

Osprey's goal is to be the most trusted, transparent, and effective browser protection extension for home users and
businesses, while being **free, forever**. Unlike other free extensions, Osprey will **never** collect, profile, or sell
your browsing data.

###

You can check Osprey's real-time protection status by left-clicking the ![Icon](https://i.imgur.com/E1SM8OJ.png)
extension icon in your browser's toolbar:

![Popup Panel](https://i.imgur.com/0MaOw9D.png)

###

The settings page allows you to configure which protection providers Osprey uses to check websites:

![Settings Page](https://i.imgur.com/pjhiy6R.png)

###

You can even add your own API keys for third-party integrations that support it:

![Third-Party Integrations](https://i.imgur.com/xzYLywa.png)

###

When Osprey blocks a website, you'll see a warning page like this:

![Warning Page](https://i.imgur.com/RZZ82Kr.png)

## Our Partners

Thanks to our partnered protection providers below, who've supported the project and provided exclusive access to their
premium threat intelligence feeds:

<p align="center">
  <a href="https://alphamountain.ai?utm-source=osprey" title="alphaMountain"><img src="https://i.imgur.com/7ATISNI.png" alt="alphaMountain" height="75"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://bfore.ai/?utm-source=osprey" title="BforeAI"><img src="https://i.imgur.com/GbyVoEg.png" alt="BforeAI" height="75"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://chainpatrol.com/?utm-source=osprey" title="ChainPatrol"><img src="https://i.imgur.com/lXwGX6N.png" alt="ChainPatrol" height="75"></a>
  &nbsp;&nbsp;&nbsp;&nbsp;
  <a href="https://izoologic.com/?utm-source=osprey" title="iZOOlogic"><img src="https://i.imgur.com/9DCLCdH.png" alt="iZOOlogic" height="75"></a>
</p>

and PrecisionSec, who couldn't provide a logo, but have been a great partner and supporter of the project.

## Privacy

Osprey routes every URL you visit to the protection providers you have enabled, using our privacy-respecting
[proxy server](https://github.com/OspreyProject/OspreyProxy), ensuring that providers never see your real IP address or
any personally identifiable information.

Providers only see requests originating from the proxy server's IP address, which is shared by thousands of users,
making it **impossible** for any provider to associate a URL lookup with you specifically.

We also don't log any personally identifiable information, and we don't store your browsing history. The one exception
is transient false-positive monitoring: when a provider flags a site as malicious or phishing, the proxy keeps an
in-memory record of what was checked (a domain, or a URL with query parameters stripped). It never includes your IP,
never covers safe sites, and is never written to disk, so we can catch and correct mistaken blocks. Osprey is designed
to be **privacy-first**, and we will never compromise that.

## Contact Us

Questions or concerns? Want to become a provider? Contact [support@osprey.ac](mailto:support@osprey.ac).

For support or queries, please open an issue in the [Issues section](https://github.com/OspreyProject/Osprey/issues).
