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

let reportedByText;

// Use a global singleton pattern to ensure we don't duplicate resources
// noinspection FunctionWithInconsistentReturnsJS
globalThis.WarningSingleton = globalThis.WarningSingleton || (() => {

    // Global variable for browser API compatibility
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    // The current origin integer, initialized to UNKNOWN
    let currentOriginInt = ProtectionResult.Origin.UNKNOWN;

    // Cache for DOM elements
    let domElements = {};

    /**
     * Applies visual elements based on the origin of the protection result.
     *
     * @param originInt - The integer representing the origin of the protection result.
     */
    const applyOriginVisuals = originInt => {
        const systemName = ProtectionResult.FullName[originInt];

        // Update the visible "Reported by" label
        if (domElements.reportedBy) {
            domElements.reportedBy.textContent = systemName || "Unknown";
            reportedByText = domElements.reportedBy.textContent;
        } else {
            console.warn("'reportedBy' element not found in the WarningPage DOM.");
        }
    };

    /**
     * Wraps system names text to fit within a specified maximum line length.
     *
     * @param text - The text to wrap, typically a comma-separated list of system names.
     * @returns {string} - The wrapped text, with each line not exceeding the specified maximum length.
     */
    const wrapSystemNamesText = text => {
        const parts = text.split(', ');
        const lines = [];
        let currentLine = '';
        let maxLineLength = 110;

        for (const part of parts) {
            const nextSegment = currentLine ? `${currentLine}, ${part}` : part;

            if (nextSegment.length <= maxLineLength) {
                currentLine = nextSegment;
            } else {
                if (currentLine) {
                    lines.push(currentLine);
                }

                currentLine = part;
            }
        }

        if (currentLine) {
            lines.push(currentLine);
        }
        return lines.join('\n');
    };

    /**
     * Initialize the popup or refresh if already initialized.
     */
    const initialize = () => {
        // Initializes the DOM element cache
        domElements = Object.fromEntries(
            ["reason", "url", "reportedBy", "reportWebsite", "allowWebsite", "backButton", "continueButton",
                "warningTitle", "recommendation", "details", "urlLabel", "reportedByLabel", "reasonLabel", "logo",
                "reportBreakpoint"]
                .map(id => [id, document.getElementById(id)])
        );

        // Extracts the threat code from the current page URL
        const pageUrl = globalThis.document.URL;
        const result = UrlHelpers.extractResult(pageUrl);

        // Checks if the result is valid
        if (!result) {
            console.warn("No result found in the URL.");
            return;
        }

        // Converts the result code to a human-readable string
        const resultText = ProtectionResult.ResultTypeName[result];
        const resultTextEN = ProtectionResult.ResultTypeNameEN[result];

        /**
         * Localizes the page by replacing text content with localized messages.
         */
        const localizePage = () => {
            const bannerText = document.querySelector('.bannerText');

            // Sets the document title text
            if (document.title) {
                document.title = LangUtil.TITLE;
            } else {
                console.warn("Document title element not found for the WarningPage.");
            }

            // Sets the banner text
            if (bannerText) {
                bannerText.textContent = LangUtil.TITLE;
            } else {
                console.warn("'bannerText' element not found in the WarningPage DOM.");
            }

            // Sets the warning title text
            if (domElements.warningTitle) {
                domElements.warningTitle.textContent = LangUtil.WARNING_TITLE;
            } else {
                console.warn("'warningTitle' element not found in the WarningPage DOM.");
            }

            // Sets the recommendation text
            if (domElements.recommendation) {
                domElements.recommendation.textContent = LangUtil.RECOMMENDATION;
            } else {
                console.warn("'recommendation' element not found in the WarningPage DOM.");
            }

            // Sets the details text
            if (domElements.details) {
                domElements.details.textContent = LangUtil.DETAILS;
            } else {
                console.warn("'details' element not found in the WarningPage DOM.");
            }

            // Sets the URL label text
            if (domElements.urlLabel) {
                domElements.urlLabel.textContent = LangUtil.URL_LABEL;
            } else {
                console.warn("'urlLabel' element not found in the WarningPage DOM.");
            }

            // Sets the reported by label text
            if (domElements.reportedByLabel) {
                domElements.reportedByLabel.textContent = LangUtil.REPORTED_BY_LABEL;
            } else {
                console.warn("'reportedByLabel' element not found in the WarningPage DOM.");
            }

            // Sets the reason label text
            if (domElements.reasonLabel) {
                domElements.reasonLabel.textContent = LangUtil.REASON_LABEL;
            } else {
                console.warn("'reasonLabel' element not found in the WarningPage DOM.");
            }

            // Sets the report website button text
            if (domElements.reportWebsite) {
                domElements.reportWebsite.textContent = LangUtil.REPORT_WEBSITE;
            } else {
                console.warn("'reportWebsite' element not found in the WarningPage DOM.");
            }

            // Sets the allow website button text
            if (domElements.allowWebsite) {
                domElements.allowWebsite.textContent = LangUtil.ALLOW_WEBSITE;
            } else {
                console.warn("'allowWebsite' element not found in the WarningPage DOM.");
            }

            // Sets the back button text
            if (domElements.backButton) {
                domElements.backButton.textContent = LangUtil.BACK_BUTTON;
            } else {
                console.warn("'backButton' element not found in the WarningPage DOM.");
            }

            // Sets the continue button text
            if (domElements.continueButton) {
                domElements.continueButton.textContent = LangUtil.CONTINUE_BUTTON;
            } else {
                console.warn("'continueButton' element not found in the WarningPage DOM.");
            }

            // Sets the alt text for the Osprey logo
            if (domElements.logo) {
                domElements.logo.alt = LangUtil.LOGO_ALT;
            } else {
                console.warn("'logo' element not found in the WarningPage DOM.");
            }
        };

        // Localizes the page content
        localizePage();

        // Sets the reason text to the extracted result
        if (domElements.reason) {
            domElements.reason.textContent = resultText;
        } else {
            console.warn("'reason' element not found in the WarningPage DOM.");
        }

        // Extracts the blocked URL from the current page URL
        const blockedUrl = UrlHelpers.extractBlockedUrl(pageUrl);

        // Encodes the URLs for safe use in other contexts
        const encodedBlockedUrl = encodeURIComponent(blockedUrl);
        const encodedResultTextEN = encodeURIComponent(resultTextEN);

        // Sets the URL text to the current page URL
        if (domElements.url) {
            domElements.url.textContent = blockedUrl;
        } else {
            console.warn("'url' element not found in the WarningPage DOM.");
        }

        // Gets the origin information
        const origin = UrlHelpers.extractOrigin(pageUrl);
        const originInt = Number.parseInt(origin);

        currentOriginInt = Number.isNaN(originInt) ? ProtectionResult.Origin.UNKNOWN : originInt;
        applyOriginVisuals(currentOriginInt);

        // Listens for PONG messages to update the reported by count
        browserAPI.runtime.onMessage.addListener(message => {
            if (domElements.reportedBy) {
                if (message.messageType === Messages.BLOCKED_COUNTER_PONG && message.count > 0) {
                    let othersText = LangUtil.REPORTED_BY_OTHERS;
                    othersText = othersText.replace("___", message.count.toString());

                    // Sets the reported by text with the count of other systems
                    domElements.reportedBy.textContent = `${reportedByText} ${othersText}`;

                    // Replace each system with its short name
                    message.systems = message.systems.map(system => ProtectionResult.ShortName[system] || system);

                    // Make the innerText hoverable and set the hover text
                    const alsoReportedBy = LangUtil.REPORTED_BY_ALSO;
                    const wrappedTitle = wrapSystemNamesText(`${alsoReportedBy}${message.systems.join(', ')}`);
                    domElements.reportedBy.title = `${wrappedTitle}`;
                } else if (message.messageType === Messages.BLOCKED_COUNTER_PONG) {
                    // If there are no "others", revert to base text & clear tooltip
                    domElements.reportedBy.textContent = reportedByText;
                    domElements.reportedBy.title = "";
                }
            } else {
                console.warn("'reportedBy' element not found in the WarningPage DOM.");
            }
        });

        // Sends a PING message to get the count of reported websites
        browserAPI.runtime.sendMessage({
            messageType: Messages.BLOCKED_COUNTER_PING
        }).catch(() => {
        });

        // Re-apply icon & re-request counts on refresh / bfcache restore
        globalThis.addEventListener('pageshow', () => {
            applyOriginVisuals(currentOriginInt);

            browserAPI.runtime.sendMessage({
                messageType: Messages.BLOCKED_COUNTER_PING
            }).catch(() => {
            });
        });

        /**
         * Gets the report URL lazily when needed.
         *
         * @returns {URL|null} - The report URL.
         */
        const getReportUrl = () => {
            switch (originInt) {
                case ProtectionResult.Origin.ADGUARD_SECURITY:
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20AdGuard%20Public%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.ADGUARD_FAMILY:
                    return new URL("mailto:support@adguard.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20AdGuard%20Family%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.ALPHAMOUNTAIN:
                    return new URL("https://alphamountain.freshdesk.com/support/tickets/new");

                case ProtectionResult.Origin.PRECISIONSEC:
                    return new URL("mailto:info@precisionsec.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20PrecisionSec%20Web%20Protection" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CERT_EE:
                    return new URL("mailto:ria@ria.ee?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CERT-EE%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CLEANBROWSING_SECURITY:
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CleanBrowsing%20Security%20Filter" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CLEANBROWSING_FAMILY:
                    return new URL("mailto:support@cleanbrowsing.org?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20CleanBrowsing%20Adult%20Filter" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CLOUDFLARE_SECURITY:
                case ProtectionResult.Origin.CLOUDFLARE_FAMILY:
                    return new URL("https://radar.cloudflare.com/domains/feedback/" + encodedBlockedUrl);

                case ProtectionResult.Origin.CONTROL_D_SECURITY:
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Control%20D%20Security%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.CONTROL_D_FAMILY:
                    return new URL("mailto:help@controld.com?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Control%20D%20Family%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.DNS4EU_SECURITY:
                case ProtectionResult.Origin.DNS4EU_FAMILY:
                    return new URL("https://www.joindns4.eu/for-public#form");

                case ProtectionResult.Origin.SWITCH_CH:
                    return new URL("mailto:dnsfirewall@switch.ch?subject=False%20Positive&body=Hello%2C" +
                        "%0A%0AI%20would%20like%20to%20report%20a%20false%20positive." +
                        "%0A%0AProduct%3A%20Switch.ch%20D%20Public%20DNS" +
                        "%0AURL%3A%20" + encodedBlockedUrl + "%20%28or%20the%20hostname%20itself%29" +
                        "%0ADetected%20as%3A%20" + encodedResultTextEN +
                        "%0A%0AI%20believe%20this%20website%20is%20legitimate." +
                        "%0A%0ASent%20with%20Osprey:%20Browser%20Protection" +
                        "%0AWebsite:%20https://osprey.ac");

                case ProtectionResult.Origin.QUAD9:
                    return new URL("https://quad9.net/support/contact");

                default:
                    return null;
            }
        };

        /**
         * Sends a message to the background script with the specified message type and additional data.
         *
         * @param messageType - The type of message to send.
         * @param additionalData - Additional data to include in the message.
         * @returns {Promise<void>} - A promise that resolves when the message is sent.
         */
        const sendMessage = async (messageType, additionalData = {}) => {
            try {
                // Creates the message object and converts URL objects to strings
                const message = {
                    messageType,
                    blockedUrl: blockedUrl instanceof URL ? blockedUrl.toString() : blockedUrl,
                    origin: origin instanceof URL ? origin.toString() : origin,
                    ...additionalData
                };

                // Converts URL objects to strings in additionalData
                for (const key in message) {
                    if (message[key] instanceof URL) {
                        message[key] = message[key].toString();
                    }
                }

                await browserAPI.runtime.sendMessage(message);
            } catch (error) {
                console.error(`Error sending message ${messageType}:`, error);
            }
        };

        // Extracts the blocked URL from the current page URL
        const continueUrl = UrlHelpers.extractContinueUrl(pageUrl);

        Settings.get(settings => {
            // Adds event listener to "Report this website as safe" button
            if (domElements.reportWebsite) {
                domElements.reportWebsite.addEventListener("click", async () => {
                    if (!settings.hideReportButton) {
                        await sendMessage(Messages.REPORT_WEBSITE, {
                            reportUrl: getReportUrl()
                        });
                    }
                });
            } else {
                console.warn("'reportWebsite' element not found in the WarningPage DOM.");
            }

            // Adds event listener to "Always ignore this website" button
            if (domElements.allowWebsite) {
                domElements.allowWebsite.addEventListener("click", async () => {
                    if (!settings.hideContinueButtons) {
                        await sendMessage(Messages.ALLOW_WEBSITE, {
                            blockedUrl: blockedUrl,
                            continueUrl: continueUrl
                        });
                    }
                });
            } else {
                console.warn("'allowWebsite' element not found in the WarningPage DOM.");
            }

            // Adds event listener to "Back to safety" button
            if (domElements.backButton) {
                domElements.backButton.addEventListener("click", async () => {
                    await sendMessage(Messages.CONTINUE_TO_SAFETY, {
                        blockedUrl: blockedUrl
                    });
                });
            } else {
                console.warn("'backButton' element not found in the WarningPage DOM.");
            }

            // Adds event listener to "Continue anyway" button
            if (domElements.continueButton) {
                domElements.continueButton.addEventListener("click", async () => {
                    if (!settings.hideContinueButtons) {
                        await sendMessage(Messages.CONTINUE_TO_WEBSITE, {
                            blockedUrl: blockedUrl,
                            continueUrl: continueUrl
                        });
                    }
                });
            } else {
                console.warn("'continueButton' element not found in the WarningPage DOM.");
            }

            // Handles the hide continue buttons policy
            if (!settings.hideContinueButtons) {
                if (domElements.allowWebsite) {
                    domElements.allowWebsite.style.display = "";
                } else {
                    console.warn("'allowWebsite' element not found in the WarningPage DOM.");
                }

                if (domElements.continueButton) {
                    domElements.continueButton.style.display = "";
                } else {
                    console.warn("'continueButton' element not found in the WarningPage DOM.");
                }
            }

            // Handles the hide report button policy
            if (!settings.hideReportButton) {
                if (domElements.reportWebsite) {
                    domElements.reportWebsite.style.display = "";
                } else {
                    console.warn("'reportWebsite' element not found in the WarningPage DOM.");
                }

                if (domElements.reportBreakpoint) {
                    domElements.reportBreakpoint.style.display = "";
                } else {
                    console.warn("'reportBreakpoint' element not found in the WarningPage DOM.");
                }
            }

            // Handles the back button visibility
            if (domElements.backButton) {
                domElements.backButton.style.display = "";
            } else {
                console.warn("'backButton' element not found in the WarningPage DOM.");
            }
        });
    };

    return {
        initialize
    };
})();

// Initializes when the DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    globalThis.WarningSingleton.initialize();
});
