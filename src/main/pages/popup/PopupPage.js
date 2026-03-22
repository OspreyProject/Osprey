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

// Use a global singleton pattern to ensure we don't duplicate resources
globalThis.PopupSingleton = globalThis.PopupSingleton || (() => {

    // Global variable for browser API compatibility
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    // Tracks initialization state
    let isInitialized = false;

    // Cache for system elements
    const systemElements = {};

    // Cache for DOM elements
    let domElements = {};

    /**
     * Creates a security system descriptor.
     *
     * @param {string} origin The ProtectionResult.Origin value.
     * @param {string} name The settings key name.
     * @param {string} labelElementId The status label element ID.
     * @param {string} switchElementId The toggle switch element ID.
     * @param {string} messageType The message type for background communication.
     * @returns {Object} Frozen system descriptor.
     */
    const makeSystem = (origin, name, labelElementId, switchElementId, messageType) => Object.freeze({
        origin,
        name,
        labelElementId,
        switchElementId,
        messageType,
    });

    // Security systems configuration; only defined once
    const securitySystems = Object.freeze([
        makeSystem(ProtectionResult.Origin.ADGUARD_SECURITY, "adGuardSecurityEnabled", "adGuardSecurityStatus", "adGuardSecuritySwitch", Messages.ADGUARD_SECURITY_TOGGLED),
        makeSystem(ProtectionResult.Origin.ADGUARD_FAMILY, "adGuardFamilyEnabled", "adGuardFamilyStatus", "adGuardFamilySwitch", Messages.ADGUARD_FAMILY_TOGGLED),
        makeSystem(ProtectionResult.Origin.ALPHAMOUNTAIN, "alphaMountainEnabled", "alphaMountainStatus", "alphaMountainSwitch", Messages.ALPHAMOUNTAIN_TOGGLED),
        makeSystem(ProtectionResult.Origin.PRECISIONSEC, "precisionSecEnabled", "precisionSecStatus", "precisionSecSwitch", Messages.PRECISIONSEC_TOGGLED),
        makeSystem(ProtectionResult.Origin.CERT_EE, "certEEEnabled", "certEEStatus", "certEESwitch", Messages.CERT_EE_TOGGLED),
        makeSystem(ProtectionResult.Origin.CLEANBROWSING_SECURITY, "cleanBrowsingSecurityEnabled", "cleanBrowsingSecurityStatus", "cleanBrowsingSecuritySwitch", Messages.CLEANBROWSING_SECURITY_TOGGLED),
        makeSystem(ProtectionResult.Origin.CLEANBROWSING_FAMILY, "cleanBrowsingFamilyEnabled", "cleanBrowsingFamilyStatus", "cleanBrowsingFamilySwitch", Messages.CLEANBROWSING_FAMILY_TOGGLED),
        makeSystem(ProtectionResult.Origin.CLOUDFLARE_SECURITY, "cloudflareSecurityEnabled", "cloudflareSecurityStatus", "cloudflareSecuritySwitch", Messages.CLOUDFLARE_SECURITY_TOGGLED),
        makeSystem(ProtectionResult.Origin.CLOUDFLARE_FAMILY, "cloudflareFamilyEnabled", "cloudflareFamilyStatus", "cloudflareFamilySwitch", Messages.CLOUDFLARE_FAMILY_TOGGLED),
        makeSystem(ProtectionResult.Origin.CONTROL_D_SECURITY, "controlDSecurityEnabled", "controlDSecurityStatus", "controlDSecuritySwitch", Messages.CONTROL_D_SECURITY_TOGGLED),
        makeSystem(ProtectionResult.Origin.CONTROL_D_FAMILY, "controlDFamilyEnabled", "controlDFamilyStatus", "controlDFamilySwitch", Messages.CONTROL_D_FAMILY_TOGGLED),
        makeSystem(ProtectionResult.Origin.PHISH_DESTROY, "phishDestroyEnabled", "phishDestroyStatus", "phishDestroySwitch", Messages.PHISH_DESTROY_TOGGLED),
        makeSystem(ProtectionResult.Origin.PHISHING_DATABASE, "phishingDatabaseEnabled", "phishingDatabaseStatus", "phishingDatabaseSwitch", Messages.PHISHING_DATABASE_TOGGLED),
        makeSystem(ProtectionResult.Origin.QUAD9, "quad9Enabled", "quad9Status", "quad9Switch", Messages.QUAD9_TOGGLED),
        makeSystem(ProtectionResult.Origin.SWITCH_CH, "switchCHEnabled", "switchCHStatus", "switchCHSwitch", Messages.SWITCH_CH_TOGGLED),
    ]);

    /**
     * Gets DOM elements for a system, caching them for future use.
     *
     * @param {Object} system The system object
     * @returns {Object} Object containing the label and switch elements
     */
    const getSystemElements = system => {
        if (!system) {
            console.warn(`Invalid system object provided to getSystemElements:`, system);
            return null;
        }

        if (!systemElements[system.name]) {
            systemElements[system.name] = {
                label: document.getElementById(system.labelElementId),
                switchElement: document.getElementById(system.switchElementId)
            };
        }
        return systemElements[system.name];
    };

    /**
     * Updates the UI for a specific security system using batched DOM operations.
     *
     * @param {Object} system The system object being updated.
     * @param {boolean} isOn Whether the protection is enabled for the system.
     * @param {boolean} isLocked Whether protection options are currently locked.
     */
    const updateProtectionStatusUI = (system, isOn, isLocked) => {
        const elements = getSystemElements(system);

        if (!elements) {
            console.warn(`Could not retrieve elements for ${system.name}; skipping UI update.`);
            return;
        }

        if (elements.label) {
            if (isLocked) {
                elements.label.textContent = isOn ? LangUtil.ON_LOCKED_TEXT : LangUtil.OFF_LOCKED_TEXT;
            } else {
                elements.label.textContent = isOn ? LangUtil.ON_TEXT : LangUtil.OFF_TEXT;
            }
        } else {
            console.warn(`'label' element not found for ${system.name} in the PopupPage DOM.`);
        }

        if (elements.switchElement) {
            if (isOn) {
                elements.switchElement.classList.add("on");
                elements.switchElement.classList.remove("off");
                elements.switchElement.setAttribute("aria-checked", "true");
            } else {
                elements.switchElement.classList.remove("on");
                elements.switchElement.classList.add("off");
                elements.switchElement.setAttribute("aria-checked", "false");
            }
        } else {
            console.warn(`'switchElement' not found for ${system.name} in the PopupPage DOM.`);
        }
    };

    /**
     * Toggles the state of a security system and updates its UI.
     *
     * @param {Object} system The system object being toggled.
     */
    const toggleProtection = system => {
        Settings.get(settings => {
            if (!settings || typeof settings !== 'object') {
                console.error(`PopupPage: Settings.get returned invalid settings in toggleProtection for ${system.name}; aborting toggle.`);
                return;
            }

            const newState = !settings[system.name];

            Settings.set({[system.name]: newState}, () => {
                Settings.get(verified => {
                    if (!verified || typeof verified !== 'object') {
                        console.error(`PopupPage: Could not verify settings write for ${system.name}; aborting UI update.`);
                        return;
                    }

                    if (verified[system.name] !== newState) {
                        console.error(`PopupPage: Settings write verification failed for ${system.name}; expected ${newState}, got ${verified[system.name]}.`);
                        return;
                    }

                    updateProtectionStatusUI(system, newState, verified.lockProtectionOptions);

                    browserAPI.runtime.sendMessage({
                        messageType: system.messageType,
                        title: ProtectionResult.FullName[system.origin],
                        toggleState: newState,
                    }).catch(error => {
                        console.error(`Failed to send message for ${system.name}:`, error);
                    });
                });
            });
        });
    };

    /**
     * Resets to initial state to prevent memory leaks.
     */
    const reset = () => {
        // Removes click handlers from all switches
        for (const system of securitySystems) {
            const elements = systemElements[system.name];

            if (elements?.switchElement) {
                elements.switchElement.onclick = null;
                elements.switchElement.onkeydown = null;
            }
        }

        // Removes click handlers from pagination arrows
        if (domElements.prevPage) {
            domElements.prevPage.onclick = null;
            domElements.prevPage.onkeydown = null;
        }
        if (domElements.nextPage) {
            domElements.nextPage.onclick = null;
            domElements.nextPage.onkeydown = null;
        }

        // Keeps the DOM elements cache, but resets initialized status
        isInitialized = false;
    };

    /**
     * Initializes the popup or refresh if already initialized.
     */
    const initialize = () => {
        // If already initialized, reset first
        if (isInitialized) {
            reset();
        }

        // Initializes the DOM element cache
        domElements = Object.fromEntries(
            ["popupTitle", "githubLink", "version", "privacyPolicy", "logo", "prevPage", "nextPage", "pageIndicator"]
                .map(id => [id, document.getElementById(id)])
        );

        // Marks initialized as true
        isInitialized = true;

        /**
         * Localizes the page by replacing text content with localized messages.
         */
        const localizePage = () => {
            const bannerText = document.querySelector('.bannerText');

            // Sets the document title text
            document.title = LangUtil.TITLE;

            // Sets the banner text
            if (bannerText) {
                bannerText.textContent = LangUtil.TITLE;
            } else {
                console.warn("'bannerText' element not found in the PopupPage DOM.");
            }

            // Sets titles and aria-labels for star symbols and partner labels
            const officialPartnerTitle = LangUtil.OFFICIAL_PARTNER_TITLE;
            for (const element of document.querySelectorAll('.starSymbol, .partnerLabel')) {
                element.setAttribute('title', officialPartnerTitle);
                element.setAttribute('aria-label', officialPartnerTitle);
            }

            // Sets the alt text for the Osprey logo
            if (domElements.logo) {
                domElements.logo.alt = LangUtil.LOGO_ALT;
            } else {
                console.warn("'logo' element not found in the PopupPage DOM.");
            }

            // Sets the popup title text
            if (domElements.popupTitle) {
                domElements.popupTitle.textContent = LangUtil.POPUP_TITLE;
            } else {
                console.warn("'popupTitle' element not found in the PopupPage DOM.");
            }

            // Sets the GitHub link text
            if (domElements.githubLink) {
                domElements.githubLink.textContent = LangUtil.GITHUB_LINK;
            } else {
                console.warn("'githubLink' element not found in the PopupPage DOM.");
            }

            // Sets the Privacy Policy text
            if (domElements.privacyPolicy) {
                domElements.privacyPolicy.textContent = LangUtil.PRIVACY_POLICY;
            } else {
                console.warn("'privacyPolicy' element not found in the PopupPage DOM.");
            }
        };

        // Localizes the page content
        localizePage();

        // Sets up switch elements and click handlers
        for (const system of securitySystems) {
            const elements = getSystemElements(system);

            if (!elements) {
                continue;
            }

            if (elements.switchElement) {
                elements.switchElement.onclick = () => {
                    Settings.get(settings => {
                        if (!settings || typeof settings !== 'object') {
                            console.error("PopupPage: Settings.get returned invalid settings in switch handler; aborting toggle.");
                            return;
                        }

                        if (settings.lockProtectionOptions) {
                            console.debug("Protections are locked; cannot toggle.");
                        } else {
                            toggleProtection(system);
                        }
                    });
                };

                elements.switchElement.onkeydown = e => {
                    if (e.key === " " || e.key === "Enter") {
                        e.preventDefault();
                        elements.switchElement.click();
                    }
                };
            } else {
                console.warn(`'switchElement' not found for ${system.name} in the PopupPage DOM; cannot set click handler.`);
            }
        }

        // Loads and applies settings
        Settings.get(settings => {
            for (const system of securitySystems) {
                updateProtectionStatusUI(system, settings[system.name], settings.lockProtectionOptions);
            }
        });

        // Updates the version display
        if (domElements.version) {
            domElements.version.textContent = LangUtil.VERSION + browserAPI.runtime.getManifest().version;
        }

        // Get all elements with the class 'page'
        const pages = document.querySelectorAll('.page');
        let currentPage = 1;
        const totalPages = pages.length;

        // Checks if there are no pages
        if (totalPages === 0) {
            console.error('No pages found. Please ensure there are elements with the class "page".');
            return;
        }

        const updatePageDisplay = (newPage) => {
            if (newPage < 1 || newPage > totalPages) {
                return;
            }

            pages[currentPage - 1].classList.remove('active');
            currentPage = newPage;
            pages[currentPage - 1].classList.add('active');

            if (domElements.pageIndicator) {
                domElements.pageIndicator.textContent = `${currentPage}/${totalPages}`;
                domElements.pageIndicator.setAttribute('aria-label', `${LangUtil.PAGE_INDICATOR_LABEL} ${currentPage} ${LangUtil.PAGE_INDICATOR_OF} ${totalPages}`);
            } else {
                console.warn("'pageIndicator' element not found in the PopupPage DOM.");
            }
        };

        if (domElements.prevPage) {
            domElements.prevPage.onclick = () => {
                updatePageDisplay(currentPage === 1 ? totalPages : currentPage - 1);
            };

            domElements.prevPage.onkeydown = e => {
                if (e.key === " " || e.key === "Enter") {
                    e.preventDefault();
                    domElements.prevPage.click();
                }
            };
        } else {
            console.warn("'prevPage' element not found in the PopupPage DOM.");
        }

        if (domElements.nextPage) {
            domElements.nextPage.onclick = () => {
                updatePageDisplay(currentPage === totalPages ? 1 : currentPage + 1);
            };

            domElements.nextPage.onkeydown = e => {
                if (e.key === " " || e.key === "Enter") {
                    e.preventDefault();
                    domElements.nextPage.click();
                }
            };
        } else {
            console.warn("'nextPage' element not found in the PopupPage DOM.");
        }

        // Initializes the page display
        updatePageDisplay(1);
    };

    return Object.freeze({
        initialize
    });
})();

// Initializes when the DOM is ready
document.addEventListener("DOMContentLoaded", () => {
    try {
        Settings.get(settings => {
            if (!settings || typeof settings !== 'object' || settings.hideProtectionOptions) {
                globalThis.close();
            } else {
                globalThis.PopupSingleton.initialize();
            }
        });
    } catch (e) {
        console.error("PopupPage failed to initialize:", e);
    }
});
