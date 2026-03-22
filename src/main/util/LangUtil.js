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

{
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    /**
     * Retrieves a localized message by key, warning if the key is missing or unregistered.
     *
     * @param {string} key The i18n message key.
     * @returns {string} The localized message, or the key name if not found.
     */
    const msg = key => {
        if (typeof key !== 'string' || key.length === 0) {
            console.warn(`LangUtil: msg() called with invalid key: ${key}`);
            return '';
        }

        if (!browserAPI?.i18n?.getMessage) {
            console.error('LangUtil: browserAPI.i18n is not available');
            return key;
        }

        const value = browserAPI.i18n.getMessage(key);

        if (!value) {
            console.error(`LangUtil: missing i18n message for key '${key}'`);
            return key;
        }
        return value;
    };

    const LangUtil = Object.create(null);

    const define = (prop, key) => {
        Object.defineProperty(LangUtil, prop, {
            get() {
                return msg(key);
            },
            enumerable: true,
        });
    };

    // Global
    define('TITLE', 'extensionName');
    define('LOGO_ALT', 'logoAlt');
    define('URL_LABEL', 'urlLabel');
    define('REPORTED_BY_LABEL', 'reportedByLabel');
    define('REASON_LABEL', 'reasonLabel');

    // Background
    define('UNSAFE_WEBSITE_TITLE', 'unsafeWebsiteTitle');
    define('CLEAR_ALLOWED_WEBSITES_TITLE', 'clearAllowedWebsitesTitle');
    define('CLEAR_ALLOWED_WEBSITES_MESSAGE', 'clearAllowedWebsitesMessage');
    define('RESTORE_DEFAULTS_TITLE', 'restoreDefaultsTitle');
    define('RESTORE_DEFAULTS_MESSAGE', 'restoreDefaultsMessage');
    define('TOGGLE_NOTIFICATIONS_CONTEXT', 'toggleNotificationsContext');
    define('TOGGLE_FRAME_NAVIGATION_CONTEXT', 'toggleFrameNavigationContext');
    define('CLEAR_ALLOWED_WEBSITES_CONTEXT', 'clearAllowedWebsitesContext');
    define('REPORT_WEBSITE_AS_MALICIOUS_CONTEXT', 'reportWebsiteAsMaliciousContext');
    define('RESTORE_DEFAULTS_CONTEXT', 'restoreDefaultsContext');

    // Popup Page
    define('ON_TEXT', 'onText');
    define('OFF_TEXT', 'offText');
    define('ON_LOCKED_TEXT', 'onLockedText');
    define('OFF_LOCKED_TEXT', 'offLockedText');
    define('POPUP_TITLE', 'popupTitle');
    define('GITHUB_LINK', 'githubLink');
    define('VERSION', 'version');
    define('PRIVACY_POLICY', 'privacyPolicy');
    define('OFFICIAL_PARTNER_TITLE', 'officialPartnerTitle');

    // Warning Page
    define('WARNING_TITLE', 'warningTitle');
    define('RECOMMENDATION', 'recommendation');
    define('DETAILS', 'details');
    define('REPORT_WEBSITE', 'reportWebsite');
    define('ALLOW_WEBSITE', 'allowWebsite');
    define('BACK_BUTTON', 'backButton');
    define('CONTINUE_BUTTON', 'continueButton');
    define('REPORTED_BY_OTHERS', 'reportedByOthers');
    define('REPORTED_BY_ALSO', 'reportedByAlso');

    // Protection Result
    define('KNOWN_SAFE', 'knownSafe');
    define('FAILED', 'failed');
    define('WAITING', 'waiting');
    define('ALLOWED', 'allowed');
    define('MALICIOUS', 'malicious');
    define('PHISHING', 'phishing');
    define('UNTRUSTED', 'untrusted');
    define('ADULT_CONTENT', 'adultContent');

    Object.freeze(LangUtil);
    globalThis.LangUtil = LangUtil;
}
