/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2026 Osprey Project (https://github.com/OspreyProject)
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
"use strict";

// noinspection JSDeprecatedSymbols
(() => {
    const browserAPI = globalThis.chrome ?? globalThis.browser;
    const contextMenuAPI = browserAPI?.contextMenus ?? browserAPI?.menus;
    let supportsManagedPolicies = true;
    let redirectToGoogle = false;

    // Import necessary scripts for functionality
    try {
        importScripts(
            // Util
            "util/StorageUtil.js",
            "util/Settings.js",
            "util/UrlHelpers.js",
            "util/CacheManager.js",
            "util/MessageType.js",
            "util/LangUtil.js",
            "util/DNSMessage.js",

            // Protection
            "protection/ProtectionResult.js",
            "protection/BrowserProtection.js"
        );
    } catch (error) {
        // In Firefox-based browsers, importScripts is not available; scripts are loaded via background.html
        redirectToGoogle = true;
        console.debug("Running in Firefox or another environment without importScripts");
        console.debug(`Error: ${error}`);
    }

    // Clears the processing cache
    CacheManager.clearProcessingCache();

    // Map<tabKey, Array<origin>> (Integer) of result origins per tab
    const resultOriginsMap = new Map();

    // Map<tabKey, urlString> of frame-zero URLs per tab
    const frameZeroUrlsMap = new Map();

    /**
     * Retrieves the result origins for a specific tab.
     *
     * @param tabId - The ID of the tab.
     * @returns {any|*[]} - An array of result origins for the specified tab.
     */
    const getResultOrigins = tabId => {
        return resultOriginsMap.get(tabId) || [];
    };

    /**
     * Appends a result origin to the result origins for a specific tab.
     *
     * @param tabId - The ID of the tab.
     * @param origin - The origin to append.
     */
    const appendResultOrigin = (tabId, origin) => {
        // Check if the origin is an Integer
        if (typeof origin !== 'number' || !Number.isInteger(origin)) {
            console.warn(`Invalid origin type: ${origin}; must be an integer.`);
            return;
        }

        // Appends the origin if it doesn't already exist
        const origins = resultOriginsMap.get(tabId) || [];
        if (!origins.includes(origin)) {
            resultOriginsMap.set(tabId, [...origins, origin]);
        }
    };

    /**
     * Removes a specific origin from the result origins for a given tab.
     *
     * @param tabId - The ID of the tab.
     * @param origin - The origin to remove.
     */
    const removeResultOrigin = (tabId, origin) => {
        resultOriginsMap.set(tabId, (resultOriginsMap.get(tabId) || []).filter(o => o !== origin));
    };

    /**
     * Deletes the result origins for a specific tab.
     *
     * @param tabId - The ID of the tab.
     */
    const deleteResultOrigins = tabId => {
        resultOriginsMap.delete(tabId);
    };

    /**
     * Retrieves the frame-zero URL for a specific tab.
     *
     * @param tabId - The ID of the tab.
     */
    const getFrameZeroUrl = tabId => {
        return frameZeroUrlsMap.get(tabId) || "";
    };

    /**
     * Sets the frame-zero URL for a specific tab.
     *
     * @param tabId - The ID of the tab.
     * @param url - The URL to set.
     */
    const setFrameZeroUrl = (tabId, url) => {
        frameZeroUrlsMap.set(tabId, url);
    };

    /**
     * Deletes the frame-zero URL for a specific tab.
     *
     * @param tabId - The ID of the tab.
     */
    const deleteFrameZeroUrl = tabId => {
        frameZeroUrlsMap.delete(tabId);
    };

    /**
     * Sends the user to the new tab page.
     *
     * @param {number} tabId - The ID of the tab to be updated.
     */
    const sendToNewTabPage = tabId => {
        if (redirectToGoogle) {
            browserAPI.tabs.update(tabId, {url: "https://www.google.com"});
        } else {
            browserAPI.tabs.update(tabId, {url: "about:newtab"});
        }
    };

    // List of valid protocols to check for
    const validProtocols = new Set(['http:', 'https:']);

    /**
     * Function to handle navigation checks.
     *
     * @param navigationDetails - The navigation details to handle.
     */
    const handleNavigation = navigationDetails => {
        Settings.get(settings => {
            // Retrieves settings to check if protection is enabled
            if (Settings.allProvidersDisabled(settings)) {
                console.debug("Protection is disabled; bailing out early.");
                return;
            }

            let {tabId, frameId, url: urlString} = navigationDetails;

            // Checks if the frame ID is not the main frame
            if (settings.ignoreFrameNavigation && frameId !== 0) {
                console.debug(`Ignoring frame navigation: ${urlString} #${frameId}; bailing out.`);
                return;
            }

            // Parses the URL object
            let urlObject;
            try {
                urlObject = new URL(urlString);
            } catch (error) {
                console.warn(`Invalid URL format: ${error.message}`);
                return;
            }

            // Canonicalizes the URL
            urlObject.hash = "";
            urlObject.password = "";
            urlObject.port = "";
            urlObject.search = "";
            urlObject.username = "";

            // Debug info for the URL object
            console.debug(urlObject);

            let {hostname, protocol} = urlObject;

            // Checks if the URL has a href
            if (!urlObject.href || urlObject.href.length === 0) {
                console.debug(`URL has no href: ${urlString}; bailing out.`);
                return;
            }

            // Checks if the URL has a protocol
            if (!protocol || protocol.length === 0) {
                console.debug(`URL has no protocol: ${urlString}; bailing out.`);
                return;
            }

            let hasHostname = true;
            let previouslyBlob = false;

            // Unwraps blob: URLs safely
            if (urlObject.protocol === 'blob:') {
                try {
                    const inner = new URL(urlString.slice(5));

                    // Drops the "blob:" prefix and parses the inner URL
                    if (inner.protocol === 'http:' || inner.protocol === 'https:') {
                        urlObject = inner;
                        urlString = inner.href;
                        previouslyBlob = true;
                    } else {
                        console.debug(`Non-HTTP(S) blob origin: ${inner.protocol}; bailing out.`);
                        return;
                    }
                } catch (e) {
                    console.warn(`Invalid blob URL: ${urlString}; bailing out: ${e}`);
                    return;
                }
            }

            // Checks if the URL has a valid protocol (HTTP or HTTPS)
            if (!validProtocols.has(protocol.toLowerCase()) && !previouslyBlob) {
                console.debug(`Invalid protocol: ${protocol}; bailing out.`);
                return;
            }

            // Checks if the URL has a hostname
            if (!hostname || hostname.length === 0) {
                // This behavior is expected in blob: URLs
                if (previouslyBlob) {
                    console.debug(`Missing hostname in URL: ${urlString}; extracting from URL object.`);
                } else {
                    console.warn(`Missing hostname in URL: ${urlString}; extracting from URL object.`);
                }

                // Extracts and sets the hostname from the URL by taking the characters
                // after the first "://" and before the first "/"
                const parsedHostname = urlString.split('://')[1].split('/')[0].split(':')[0];

                if (parsedHostname) {
                    console.debug(`Extracted hostname: ${parsedHostname}`);
                    urlObject.hostname = parsedHostname;
                    hostname = parsedHostname;
                } else {
                    console.warn(`Failed to extract hostname from URL: ${urlString}; proceeding with empty hostname.`);
                    hasHostname = false;
                }
            }

            if (hasHostname) {
                // Ignores hostnames with no dots at all (excludes IPv6)
                if (!hostname.includes('.') &&
                    !hostname.includes("[") &&
                    !hostname.includes("]") &&
                    !hostname.includes(":")) {
                    console.debug(`Hostname has no dots: ${hostname}; bailing out.`);
                    return;
                }

                // Ignores hostnames with invalid trailing dot amounts
                if (hostname.endsWith('..')) {
                    console.debug(`Hostname has invalid trailing dots: ${hostname}; bailing out.`);
                    return;
                }

                // Removes www. prefix from hostname
                if (hostname.startsWith('www.')) {
                    console.debug(`Removing www. prefix from hostname: ${hostname}`);
                    hostname = hostname.slice(4);
                }

                // Removes trailing dots from hostname
                if (hostname.endsWith('.')) {
                    console.debug(`Removing trailing dots from hostname: ${hostname}`);
                    hostname = hostname.replace(/\.+$/, '');
                }

                // Excludes local/internal network addresses
                if (UrlHelpers.isInternalAddress(hostname)) {
                    console.debug(`Local/internal network URL detected: ${urlString}; bailing out.`);
                    return;
                }

                // Checks if the hostname is in the global allowed cache
                if (CacheManager.isPatternInAllowedCache(hostname, "global")) {
                    console.debug(`URL is in the global allowed cache: ${urlString}; bailing out.`);
                    return;
                }

                // Sets the cleaned hostname back to the URL object
                urlObject.hostname = hostname;
            }

            // Removes trailing slashes from pathname
            if (urlObject.pathname.endsWith('/') && urlObject.pathname.length > 1) {
                urlObject.pathname = urlObject.pathname.replace(/\/+$/, '');
            }

            // Re-builds the URL string, sets it to the href if hostname is missing
            if (hasHostname) {
                urlString = "https://" + hostname + urlObject.pathname;
            } else {
                console.warn(`Hostname is missing; using full href: ${urlObject.href}`);
                urlString = urlObject.href;
            }

            // Cancels all pending requests for the main frame navigation
            if (frameId === 0) {
                BrowserProtection.abandonPendingRequests(tabId, "Cancelled by main frame navigation.");

                // Removes all cached keys for the tab
                CacheManager.removeKeysByTabId(tabId);

                // Sets the frame-zero URL for the tab
                setFrameZeroUrl(tabId, urlString);
            }

            let blocked = false;
            let firstOrigin = ProtectionResult.Origin.UNKNOWN;

            // Clears result origins for the tab
            deleteResultOrigins(tabId);

            const startTime = Date.now();
            console.info("Checking URL:", urlString);

            // Checks if the URL is malicious
            BrowserProtection.checkIfUrlIsMalicious(tabId, urlString, result => {
                const duration = Date.now() - startTime;
                const cacheName = ProtectionResult.CacheName[result.origin];
                const fullName = ProtectionResult.FullName[result.origin];
                const shortName = ProtectionResult.ShortName[result.origin];
                const {resultType} = result;
                const resultTypeNameEN = ProtectionResult.ResultTypeNameEN[resultType];

                // Removes the URL from the system's processing cache on every callback
                // Doesn't remove it if the result is still waiting for a response
                if (resultType !== ProtectionResult.ResultType.WAITING) {
                    CacheManager.removeUrlFromProcessingCache(urlObject, cacheName);
                }

                console.info(`[${shortName}] Result for ${urlString}: ${resultTypeNameEN} (${duration}ms)`);

                if (resultType !== ProtectionResult.ResultType.FAILED &&
                    resultType !== ProtectionResult.ResultType.WAITING &&
                    resultType !== ProtectionResult.ResultType.KNOWN_SAFE &&
                    resultType !== ProtectionResult.ResultType.ALLOWED) {

                    if (!blocked) {
                        browserAPI.tabs.get(tabId, tab => {
                            // Checks if the tab or tab.url is undefined
                            if (tab?.url === undefined) {
                                console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                                return;
                            }

                            const pendingUrl = tab.pendingUrl || tab.url;

                            // Checks if the tab is at an extension page
                            if (!(urlString !== pendingUrl && frameId === 0) &&
                                (pendingUrl.startsWith("chrome-extension:") ||
                                    pendingUrl.startsWith("moz-extension:") ||
                                    pendingUrl.startsWith("extension:"))) {
                                console.debug(`[${shortName}] The tab is at an extension page; bailing out. ${pendingUrl} ${frameId}`);
                                return;
                            }

                            const targetUrl = frameId === 0 ? urlString : pendingUrl;

                            if (targetUrl) {
                                const frameZeroUrl = getFrameZeroUrl(tabId);
                                const blockPageUrl = UrlHelpers.getBlockPageUrl(result, frameZeroUrl === undefined ? result.url : frameZeroUrl);

                                // Navigates to the block page
                                console.debug(`[${shortName}] Navigating to block page: ${blockPageUrl}.`);
                                browserAPI.tabs.update(tab.id, {url: blockPageUrl}).catch(error => {
                                    console.error(`Failed to update tab ${tabId}:`, error);
                                    sendToNewTabPage(tabId);
                                });

                                // Builds the warning notification options
                                if (settings.notificationsEnabled) {
                                    const notificationOptions = {
                                        type: "basic",
                                        iconUrl: "assets/icons/icon128.png",
                                        title: LangUtil.UNSAFE_WEBSITE_TITLE,
                                        message: `${LangUtil.URL_LABEL}${urlString}\n${LangUtil.REPORTED_BY_LABEL}${fullName}\n${LangUtil.REASON_LABEL}${resultTypeNameEN}`,
                                        priority: 2,
                                    };

                                    // Creates a unique notification ID based on a random number
                                    const randomNumber = Math.floor(Math.random() * 100000000);
                                    const notificationId = `warning-${randomNumber}`;

                                    // Displays the warning notification
                                    browserAPI.notifications.create(notificationId, notificationOptions, notificationId => {
                                        console.debug(`Notification created with ID: ${notificationId}`);
                                    });
                                }
                            } else {
                                console.debug(`Tab '${tabId}' failed to supply a top-level URL; bailing out.`);
                            }
                        });
                    }

                    blocked = true;
                    firstOrigin = firstOrigin === ProtectionResult.Origin.UNKNOWN ? result.origin : firstOrigin;

                    // Appends the result origin to the tab's result origins
                    // Doesn't include the first origin in the list
                    if (result.origin !== firstOrigin) {
                        appendResultOrigin(tabId, result.origin);
                    }

                    const blockedCounterDelay = 150;

                    // This timeout is needed to prevent visual artifacts on page load
                    setTimeout(() => {
                        const resultOrigins = getResultOrigins(tabId);
                        const fullCount = (Array.isArray(resultOrigins) ? resultOrigins.length : 0) + 1;
                        const othersCount = Array.isArray(resultOrigins) ? resultOrigins.length : 0;

                        // Sets the action text to the result count
                        browserAPI.action.setBadgeText({text: `${fullCount}`, tabId});
                        browserAPI.action.setBadgeBackgroundColor({color: "rgb(255,75,75)", tabId});
                        browserAPI.action.setBadgeTextColor({color: "white", tabId});

                        // If the page URL is the block page, send (count - 1)
                        browserAPI.tabs.get(tabId, tab => {
                            if (tab?.url === undefined) {
                                console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                                return;
                            }

                            // Sends a PONG message to the content script to update the blocked counter
                            browserAPI.tabs.sendMessage(tabId, {
                                messageType: Messages.BLOCKED_COUNTER_PONG,
                                count: othersCount,
                                systems: resultOrigins || []
                            }).catch(() => {
                            });
                        });
                    }, blockedCounterDelay);
                }
            });
        });
    };

    /**
     * Creates the context menu for the extension.
     */
    const createContextMenu = () => {
        Settings.get(settings => {
            // Removes existing menu items to avoid duplicates
            contextMenuAPI.removeAll();

            // Checks if the context menu is disabled by policies
            if (!settings.contextMenuEnabled) {
                return;
            }

            // Creates the toggle notifications menu item
            contextMenuAPI.create({
                id: "toggleNotifications",
                title: LangUtil.TOGGLE_NOTIFICATIONS_CONTEXT,
                type: "checkbox",
                checked: settings.notificationsEnabled,
                contexts: ["action"],
            });

            // Creates the toggle frame navigation menu item
            contextMenuAPI.create({
                id: "toggleFrameNavigation",
                title: LangUtil.TOGGLE_FRAME_NAVIGATION_CONTEXT,
                type: "checkbox",
                checked: settings.ignoreFrameNavigation,
                contexts: ["action"],
            });

            // Creates the clear allowed websites menu item
            contextMenuAPI.create({
                id: "clearAllowedWebsites",
                title: LangUtil.CLEAR_ALLOWED_WEBSITES_CONTEXT,
                contexts: ["action"],
            });

            // Creates the report website as malicious menu item
            contextMenuAPI.create({
                id: "reportWebsiteAsMalicious",
                title: LangUtil.REPORT_WEBSITE_AS_MALICIOUS_CONTEXT,
                contexts: ["action"],
            });

            // Creates the restore default settings menu item
            contextMenuAPI.create({
                id: "restoreDefaultSettings",
                title: LangUtil.RESTORE_DEFAULTS_CONTEXT,
                contexts: ["action"],
            });

            // Returns early if managed policies are not supported
            if (!supportsManagedPolicies) {
                return;
            }

            // Gathers the policy values for updating the context menu
            const policyKeys = [
                "DisableNotifications",
                "DisableClearAllowedWebsites",
                "DisableReportWebsiteAsMalicious",
                "IgnoreFrameNavigation",
                "DisableRestoreDefaultSettings"
            ];

            browserAPI.storage.managed.get(policyKeys, policies => {
                let updatedSettings = {};

                // Checks if the enable notifications button should be disabled
                if (policies.DisableNotifications !== undefined) {
                    contextMenuAPI.update("toggleNotifications", {
                        enabled: false,
                        checked: !policies.DisableNotifications,
                    });

                    updatedSettings.notificationsEnabled = !policies.DisableNotifications;
                    console.debug("Notifications are managed by system policy.");
                }

                // Checks if the ignore frame navigation button should be disabled
                if (policies.IgnoreFrameNavigation !== undefined) {
                    contextMenuAPI.update("toggleFrameNavigation", {
                        enabled: false,
                        checked: policies.IgnoreFrameNavigation,
                    });

                    updatedSettings.ignoreFrameNavigation = policies.IgnoreFrameNavigation;
                    console.debug("Ignoring frame navigation is managed by system policy.");
                }

                // Checks if the clear allowed websites button should be disabled
                if (policies.DisableClearAllowedWebsites !== undefined && policies.DisableClearAllowedWebsites) {
                    contextMenuAPI.update("clearAllowedWebsites", {
                        enabled: false,
                    });

                    console.debug("Clear allowed websites button is managed by system policy.");
                }

                // Checks if the report website as malicious button should be disabled
                if (policies.DisableReportWebsiteAsMalicious !== undefined && policies.DisableReportWebsiteAsMalicious) {
                    contextMenuAPI.update("reportWebsiteAsMalicious", {
                        enabled: false,
                    });

                    console.debug("Report website as malicious button is managed by system policy.");
                }

                // Checks if the restore default settings button should be disabled
                if (policies.DisableRestoreDefaultSettings !== undefined && policies.DisableRestoreDefaultSettings) {
                    contextMenuAPI.update("restoreDefaultSettings", {
                        enabled: false,
                    });

                    console.debug("Restore default settings button is managed by system policy.");
                }

                // Updates settings cumulatively if any policy-based changes were made
                if (Object.keys(updatedSettings).length > 0) {
                    Settings.set(updatedSettings, () => {
                        console.debug("Updated settings from context menu creation:", updatedSettings);
                    });
                }
            });
        });
    };

    // Sets all policy keys needed for managed policies
    const policyKeys = [
        'DisableContextMenu',
        'DisableNotifications',
        'HideContinueButtons',
        'HideReportButton',
        'IgnoreFrameNavigation',
        'CacheExpirationSeconds',
        'LockProtectionOptions',
        'HideProtectionOptions',

        // Official Partners
        'AdGuardSecurityEnabled',
        'AdGuardFamilyEnabled',
        'AlphaMountainEnabled',
        'ControlDSecurityEnabled',
        'ControlDFamilyEnabled',
        'PrecisionSecEnabled',

        // Non-Partnered Providers
        'CERTEEEnabled',
        'CleanBrowsingSecurityEnabled',
        'CleanBrowsingFamilyEnabled',
        'CloudflareSecurityEnabled',
        'CloudflareFamilyEnabled',
        'DNS4EUSecurityEnabled',
        'DNS4EUFamilyEnabled',
        'SeclookupEnabled',
        'SwitchCHEnabled',
        'Quad9Enabled',
    ];

    // Creates the context menu and sets managed policies
    browserAPI.storage.managed.get(policyKeys, policies => {
        if (policies === undefined) {
            supportsManagedPolicies = false;
            console.debug("Managed policies are not supported or setup correctly in this browser.");
        } else {
            supportsManagedPolicies = true;
            let settings = {};

            // Checks and sets the context menu settings using the policy
            if (policies.DisableContextMenu !== undefined && policies.DisableContextMenu === true) {
                settings.contextMenuEnabled = false;
                console.debug("Context menu is disabled by system policy.");
            } else {
                settings.contextMenuEnabled = true;
            }

            const defaultCacheExpiration = 604800; // 7 days in seconds

            // Checks and sets the cache expiration time using the policy
            if (policies.CacheExpirationSeconds === undefined) {
                settings.cacheExpirationSeconds = defaultCacheExpiration;
            } else {
                const minSeconds = 60;

                if (typeof policies.CacheExpirationSeconds !== "number" || policies.CacheExpirationSeconds < minSeconds) {
                    settings.cacheExpirationSeconds = defaultCacheExpiration;
                    console.debug("Cache expiration time is invalid; using default value.");
                } else {
                    settings.cacheExpirationSeconds = policies.CacheExpirationSeconds;
                    console.debug(`Cache expiration time set to: ${policies.CacheExpirationSeconds}`);
                }
            }

            // Checks and sets the continue buttons settings using the policy
            if (policies.HideContinueButtons !== undefined && policies.HideContinueButtons === true) {
                settings.hideContinueButtons = policies.HideContinueButtons;
                console.debug("Continue buttons are managed by system policy.");
            } else {
                settings.hideContinueButtons = false;
            }

            // Checks and sets the report button settings using the policy
            if (policies.HideReportButton !== undefined && policies.HideReportButton === true) {
                settings.hideReportButton = policies.HideReportButton;
                console.debug("Report button is managed by system policy.");
            } else {
                settings.hideReportButton = false;
            }

            // Checks and sets the lock protection options using the policy
            if (policies.LockProtectionOptions !== undefined && policies.LockProtectionOptions === true) {
                settings.lockProtectionOptions = policies.LockProtectionOptions;
                console.debug("Protection options are locked by system policy.");
            } else {
                settings.lockProtectionOptions = false;
            }

            // Checks and sets the hide protection options using the policy
            if (policies.HideProtectionOptions !== undefined && policies.HideProtectionOptions === true) {
                settings.hideProtectionOptions = policies.HideProtectionOptions;
                console.debug("Protection options are hidden by system policy.");
            } else {
                settings.hideProtectionOptions = false;
            }

            // Checks and sets the AdGuard Security settings using the policy
            if (policies.AdGuardSecurityEnabled !== undefined) {
                settings.adGuardSecurityEnabled = policies.AdGuardSecurityEnabled;
                console.debug("AdGuard Security is managed by system policy.");
            }

            // Checks and sets the AdGuard Family settings using the policy
            if (policies.AdGuardFamilyEnabled !== undefined) {
                settings.adGuardFamilyEnabled = policies.AdGuardFamilyEnabled;
                console.debug("AdGuard Family is managed by system policy.");
            }

            // Checks and sets the alphaMountain settings using the policy
            if (policies.AlphaMountainEnabled !== undefined) {
                settings.alphaMountainEnabled = policies.AlphaMountainEnabled;
                console.debug("alphaMountain Web Protection is managed by system policy.");
            }

            // Checks and sets the PrecisionSec settings using the policy
            if (policies.PrecisionSecEnabled !== undefined) {
                settings.precisionSecEnabled = policies.PrecisionSecEnabled;
                console.debug("PrecisionSec is managed by system policy.");
            }

            // Checks and sets the CERT-EE settings using the policy
            if (policies.CERTEEEnabled !== undefined) {
                settings.certEEEnabled = policies.CERTEEEnabled;
                console.debug("CERT-EE is managed by system policy.");
            }

            // Checks and sets the CleanBrowsing Security settings using the policy
            if (policies.CleanBrowsingSecurityEnabled !== undefined) {
                settings.cleanBrowsingSecurityEnabled = policies.CleanBrowsingSecurityEnabled;
                console.debug("CleanBrowsing Security is managed by system policy.");
            }

            // Checks and sets the CleanBrowsing Family settings using the policy
            if (policies.CleanBrowsingFamilyEnabled !== undefined) {
                settings.cleanBrowsingFamilyEnabled = policies.CleanBrowsingFamilyEnabled;
                console.debug("CleanBrowsing Family is managed by system policy.");
            }

            // Checks and sets the Cloudflare Security settings using the policy
            if (policies.CloudflareSecurityEnabled !== undefined) {
                settings.cloudflareSecurityEnabled = policies.CloudflareSecurityEnabled;
                console.debug("Cloudflare Security is managed by system policy.");
            }

            // Checks and sets the Cloudflare Family settings using the policy
            if (policies.CloudflareFamilyEnabled !== undefined) {
                settings.cloudflareFamilyEnabled = policies.CloudflareFamilyEnabled;
                console.debug("Cloudflare Family is managed by system policy.");
            }

            // Checks and sets the Control D Security settings using the policy
            if (policies.ControlDSecurityEnabled !== undefined) {
                settings.controlDSecurityEnabled = policies.ControlDSecurityEnabled;
                console.debug("Control D Security is managed by system policy.");
            }

            // Checks and sets the Control D Family settings using the policy
            if (policies.ControlDFamilyEnabled !== undefined) {
                settings.controlDFamilyEnabled = policies.ControlDFamilyEnabled;
                console.debug("Control D Family is managed by system policy.");
            }

            // Checks and sets the DNS4EU Security settings using the policy
            if (policies.DNS4EUSecurityEnabled !== undefined) {
                settings.dns4EUSecurityEnabled = policies.DNS4EUSecurityEnabled;
                console.debug("DNS4EU Security is managed by system policy.");
            }

            // Checks and sets the DNS4EU Family settings using the policy
            if (policies.DNS4EUFamilyEnabled !== undefined) {
                settings.dns4EUFamilyEnabled = policies.DNS4EUFamilyEnabled;
                console.debug("DNS4EU Family is managed by system policy.");
            }

            // Checks and sets the Seclookup settings using the policy
            if (policies.SeclookupEnabled !== undefined) {
                settings.seclookupEnabled = policies.SeclookupEnabled;
                console.debug("Seclookup is managed by system policy.");
            }

            // Checks and sets the Switch.ch settings using the policy
            if (policies.SwitchCHEnabled !== undefined) {
                settings.switchCHEnabled = policies.SwitchCHEnabled;
                console.debug("Switch.ch is managed by system policy.");
            }

            // Checks and sets the Quad9 settings using the policy
            if (policies.Quad9Enabled !== undefined) {
                settings.quad9Enabled = policies.Quad9Enabled;
                console.debug("Quad9 is managed by system policy.");
            }

            // Updates the stored settings if any policies were applied
            if (Object.keys(settings).length > 0) {
                Settings.set(settings, () => {
                    console.debug("Updated settings on install: ", settings);
                });
            }
        }

        // Creates the context menu
        createContextMenu();
    });

    // Listens for PING messages from content scripts to get the blocked counter
    browserAPI.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.messageType === Messages.BLOCKED_COUNTER_PING && sender.tab && sender.tab.id !== null) {
            const tabId = sender.tab.id;
            const resultOrigins = getResultOrigins(tabId);
            const fullCount = (Array.isArray(resultOrigins) ? resultOrigins.length : 0) + 1;
            const othersCount = Array.isArray(resultOrigins) ? resultOrigins.length : 0;

            // Sets the action text to the result count
            browserAPI.action.setBadgeText({text: `${fullCount}`, tabId});
            browserAPI.action.setBadgeBackgroundColor({color: "rgb(255,75,75)", tabId});
            browserAPI.action.setBadgeTextColor({color: "white", tabId});

            // If the page URL is the block page, send (count - 1)
            browserAPI.tabs.get(tabId, tab => {
                if (tab?.url === undefined) {
                    console.debug(`tabs.get(${tabId}) failed '${browserAPI.runtime.lastError?.message}'; bailing out.`);
                    return;
                }

                // Sends a PONG message to the content script to update the blocked counter
                browserAPI.tabs.sendMessage(tabId, {
                    messageType: Messages.BLOCKED_COUNTER_PONG,
                    count: othersCount,
                    systems: resultOrigins || []
                }).catch(() => {
                });

                // And responds to the original PING as well
                sendResponse({count: othersCount, systems: resultOrigins || []});
            });
            return true;
        }
        return false;
    });

    // Listens for onRemoved events
    browserAPI.tabs.onRemoved.addListener((tabId, removeInfo) => {
        console.debug(`Tab removed: ${tabId} (windowId: ${removeInfo.windowId}) (isWindowClosing: ${removeInfo.isWindowClosing})`);

        // Removes all cached keys for the tab
        CacheManager.removeKeysByTabId(tabId);

        // Removes the tab from session-backed maps
        deleteResultOrigins(tabId);
        deleteFrameZeroUrl(tabId);
    });

    // Listens for onBeforeNavigate events
    browserAPI.webNavigation.onBeforeNavigate.addListener(callback => {
        console.debug(`[onBeforeNavigate] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listens for onCommitted events
    browserAPI.webNavigation.onCommitted.addListener(callback => {
        if (callback.transitionQualifiers.includes("server_redirect") &&
            (callback.frameId !== 0 && callback.transitionType !== "start_page") ||
            callback.frameId === 0 && callback.transitionType === "link") {
            console.debug(`[server_redirect] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId}) (type: ${callback.transitionType})`);
            handleNavigation(callback);
        } else if (callback.transitionQualifiers.includes("client_redirect")) {
            console.debug(`[client_redirect] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId}) (type: ${callback.transitionType})`);
            handleNavigation(callback);
        }
    });

    // Listens for onUpdated events
    browserAPI.tabs.onUpdated.addListener((tabId, changeInfo) => {
        if (changeInfo.url?.startsWith("blob:")) {
            changeInfo.tabId = tabId;
            changeInfo.frameId = 0;

            console.debug(`[onTabUpdated] ${tabId} updated URL to ${changeInfo.url})`);
            handleNavigation(changeInfo);
        }
    });

    // Listens for onCreatedNavigationTarget events
    browserAPI.webNavigation.onCreatedNavigationTarget.addListener(callback => {
        console.debug(`[onCreatedNavigationTarget] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listens for onHistoryStateUpdated events
    browserAPI.webNavigation.onHistoryStateUpdated.addListener(callback => {
        console.debug(`[onHistoryStateUpdated] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listens for onReferenceFragmentUpdated events
    browserAPI.webNavigation.onReferenceFragmentUpdated.addListener(callback => {
        console.debug(`[onReferenceFragmentUpdated] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listens for onTabReplaced events
    browserAPI.webNavigation.onTabReplaced.addListener(callback => {
        console.debug(`[onTabReplaced] ${callback.url} (frameId: ${callback.frameId}) (tabId: ${callback.tabId})`);
        handleNavigation(callback);
    });

    // Listens for incoming messages
    browserAPI.runtime.onMessage.addListener((message, sender) => {
        // Checks if the message exists and has a valid type
        if (!message?.messageType) {
            return;
        }

        const privileged = new Set([
            Messages.CONTINUE_TO_WEBSITE,
            Messages.CONTINUE_TO_SAFETY,
            Messages.REPORT_WEBSITE,
            Messages.ALLOW_WEBSITE
        ]);

        // Gate privileged actions to the Warning page
        if (privileged.has(message.messageType)) {
            const allowedPrefix = browserAPI.runtime.getURL("pages/warning/");

            if (sender.id !== browserAPI.runtime.id || !sender.url?.startsWith(allowedPrefix)) {
                console.warn(`Blocked privileged message from ${sender.url || 'unknown source'}`);
                return;
            }
        }

        const tabId = sender.tab ? sender.tab.id : null;
        const redirectDelay = 200;

        switch (message.messageType) {
            case Messages.CONTINUE_TO_WEBSITE: {
                // Checks if the message has a blocked URL
                if (!message.blockedUrl) {
                    console.debug(`No blocked URL was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Checks if the message has a continue URL
                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Parses the blocked URL object
                let blockedUrlObject;
                try {
                    blockedUrlObject = new URL(message.blockedUrl);
                } catch (error) {
                    console.warn(`Invalid blocked URL format: ${message.blockedUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL
                if (!validProtocols.has(blockedUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Parses the continue URL object
                let continueUrlObject;
                try {
                    continueUrlObject = new URL(message.continueUrl);
                } catch (error) {
                    console.warn(`Invalid continue URL format: ${message.continueUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL
                if (!validProtocols.has(continueUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                const {origin} = message;

                if (origin === 0) {
                    console.warn(`Unknown origin: ${message.origin}`);
                } else {
                    const shortName = ProtectionResult.ShortName[origin];
                    const cacheName = ProtectionResult.CacheName[origin];

                    console.debug(`Added ${shortName} URL to allowed cache: ${message.blockedUrl}`);
                    CacheManager.addUrlToAllowedCache(message.blockedUrl, cacheName);

                    console.debug(`Removed ${shortName} URL from blocked cache: ${message.blockedUrl}`);
                    CacheManager.removeUrlFromBlockedCache(message.blockedUrl, cacheName);

                    // Remove this origin from the "remaining blockers" list for this tab
                    removeResultOrigin(tabId, origin);
                }

                browserAPI.tabs.update(tabId, {url: message.continueUrl}).catch(error => {
                    console.error(`Failed to update tab ${tabId}:`, error);
                    sendToNewTabPage(tabId);
                });
                break;
            }

            case Messages.CONTINUE_TO_SAFETY:
                // Redirects to the new tab page
                setTimeout(() => {
                    sendToNewTabPage(tabId);
                }, redirectDelay);
                break;

            case Messages.REPORT_WEBSITE: {
                // Ignores blank report URLs
                if (message.reportUrl === null || message.reportUrl === "") {
                    console.debug(`Report URL is blank.`);
                    break;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; doing nothing.`);
                    break;
                }

                let reportUrlObject = new URL(message.reportUrl);

                if (validProtocols.has(reportUrlObject.protocol.toLowerCase())) {
                    console.debug(`Navigating to report URL: ${message.reportUrl}`);
                    browserAPI.tabs.create({url: message.reportUrl});
                } else if (reportUrlObject.protocol === "mailto:") {
                    browserAPI.tabs.create({url: message.reportUrl});
                } else {
                    console.warn(`Invalid protocol in report URL: ${message.reportUrl}; doing nothing.`);
                }
                break;
            }

            case Messages.ALLOW_WEBSITE: {
                // Ignores blank blocked URLs
                if (message.blockedUrl === null || message.blockedUrl === "") {
                    console.debug(`Blocked URL is blank.`);
                    break;
                }

                // Checks if the message has a continue URL
                if (!message.continueUrl) {
                    console.debug(`No continue URL was found; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Checks if the message has an origin
                if (!message.origin) {
                    console.debug(`No origin was found; sending to the new tab page.`);
                    sendToNewTabPage(tabId);
                    break;
                }

                // Parses the blocked URL object
                let blockedUrlObject;
                try {
                    blockedUrlObject = new URL(message.blockedUrl);
                } catch (error) {
                    console.warn(`Invalid blocked URL format: ${message.blockedUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the blocked URL is not a valid HTTP(S) URL
                if (!validProtocols.has(blockedUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in blocked URL: ${message.blockedUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                const hostnameString = `*.${blockedUrlObject.hostname}`;

                // Adds the hostname to the global allowed cache
                console.debug(`Adding hostname to the global allowed cache: ${hostnameString}`);
                CacheManager.addStringToAllowedCache(hostnameString, "global");

                // Parses the continue URL object
                let continueUrlObject;
                try {
                    continueUrlObject = new URL(message.continueUrl);
                } catch (error) {
                    console.warn(`Invalid continue URL format: ${message.continueUrl}; sending to new tab page: ${error}`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Redirects to the new tab page if the continue URL is not a valid HTTP(S) URL
                if (!validProtocols.has(continueUrlObject.protocol.toLowerCase())) {
                    console.debug(`Invalid protocol in continue URL: ${message.continueUrl}; sending to new tab page.`);
                    sendToNewTabPage(tabId);
                    return;
                }

                // Sends the user to the continue URL, or the new tab page on error
                browserAPI.tabs.update(tabId, {url: message.continueUrl}).catch(error => {
                    console.error(`Failed to update tab ${tabId}:`, error);
                    sendToNewTabPage(tabId);
                });
                break;
            }

            case Messages.ADGUARD_FAMILY_TOGGLED:
            case Messages.ADGUARD_SECURITY_TOGGLED:
            case Messages.ALPHAMOUNTAIN_TOGGLED:
            case Messages.CERT_EE_TOGGLED:
            case Messages.CLEANBROWSING_FAMILY_TOGGLED:
            case Messages.CLEANBROWSING_SECURITY_TOGGLED:
            case Messages.CLOUDFLARE_FAMILY_TOGGLED:
            case Messages.CLOUDFLARE_SECURITY_TOGGLED:
            case Messages.CONTROL_D_FAMILY_TOGGLED:
            case Messages.CONTROL_D_SECURITY_TOGGLED:
            case Messages.DNS4EU_FAMILY_TOGGLED:
            case Messages.DNS4EU_SECURITY_TOGGLED:
            case Messages.PRECISIONSEC_TOGGLED:
            case Messages.SECLOOKUP_TOGGLED:
            case Messages.SWITCH_CH_TOGGLED:
            case Messages.QUAD9_TOGGLED:
                console.info(`${message.title} has been ${message.toggleState ? "enabled" : "disabled"}.`);
                break;

            case Messages.BLOCKED_COUNTER_PING:
            case Messages.BLOCKED_COUNTER_PONG:
                // This message type is used for blocked counter pings and pongs.
                break;

            default:
                console.warn(`Received unknown message type: ${message.messageType}`);
                console.warn(`Message: ${JSON.stringify(message)}`);
                break;
        }
    });

    // Listener for context menu creation.
    contextMenuAPI.onClicked.addListener(info => {
        switch (info.menuItemId) {
            case "toggleNotifications":
                Settings.set({notificationsEnabled: info.checked});
                console.debug(`Enable notifications: ${info.checked}`);
                break;

            case "toggleFrameNavigation":
                Settings.set({ignoreFrameNavigation: info.checked});
                console.debug(`Ignore frame navigation: ${info.checked}`);
                break;

            case "reportWebsiteAsMalicious": {
                // Opens the report website page in a new tab
                const reportUrl = "https://github.com/OspreyProject/Osprey/wiki/Report-Website-as-Malicious";
                browserAPI.tabs.create({url: reportUrl});
                console.debug("Opened the report website in a new tab.");
                break;
            }

            case "clearAllowedWebsites": {
                CacheManager.clearAllowedCache();
                CacheManager.clearBlockedCache();
                CacheManager.clearProcessingCache();
                console.debug("Cleared all internal website caches.");

                // Builds the browser notification to send the user
                const notificationOptions = {
                    type: "basic",
                    iconUrl: "assets/icons/icon128.png",
                    title: LangUtil.CLEAR_ALLOWED_WEBSITES_TITLE,
                    message: LangUtil.CLEAR_ALLOWED_WEBSITES_MESSAGE,
                    priority: 2,
                };

                const randomNumber = Math.floor(Math.random() * 100000000);
                const notificationId = `cache-cleared-${randomNumber}`;

                // Creates and displays the browser notification
                browserAPI.notifications.create(notificationId, notificationOptions, id => {
                    console.debug(`Notification created with ID: ${id}`);
                });
                break;
            }

            case "restoreDefaultSettings": {
                // Restores default settings
                Settings.restoreDefaultSettings();
                console.debug("Restored default settings.");

                // Builds the browser notification to send the user
                const notificationOptions = {
                    type: "basic",
                    iconUrl: "assets/icons/icon128.png",
                    title: LangUtil.RESTORE_DEFAULTS_TITLE,
                    message: LangUtil.RESTORE_DEFAULTS_MESSAGE,
                    priority: 2,
                };

                const randomNumber = Math.floor(Math.random() * 100000000);
                const notificationId = `restore-defaults-${randomNumber}`;

                // Creates and displays a browser notification
                browserAPI.notifications.create(notificationId, notificationOptions, id => {
                    console.debug(`Notification created with ID: ${id}`);
                });

                // Re-creates the context menu
                setTimeout(() => {
                    createContextMenu();
                    console.debug("Re-created context menu.");
                }, 100);
                break;
            }

            default:
                break;
        }
    });
})();
