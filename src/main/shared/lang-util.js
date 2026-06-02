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

(() => {
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const i18n = globalThis.OspreyI18n;

    const msg = (key, substitutions) => {
        if (typeof key !== 'string' || key.length === 0) {
            console.warn(`LangUtil: msg() called with invalid key: ${key}`);
            return '';
        }

        try {
            return i18n?.translate?.(key, substitutions) || browserAPI.api?.i18n?.getMessage?.(key, substitutions) || key;
        } catch (error) {
            console.error(`LangUtil: failed to resolve key '${key}'`, error);
            return key;
        }
    };

    const messageMap = Object.freeze({
        TITLE: 'extensionName',
        LOGO_ALT: 'logoAlt',
        URL_LABEL: 'urlLabel',
        REPORTED_BY_LABEL: 'reportedByLabel',
        REASON_LABEL: 'reasonLabel',

        UNSAFE_WEBSITE_TITLE: 'unsafeWebsiteTitle',
        CLEAR_ALLOWED_WEBSITES_TITLE: 'clearAllowedWebsitesTitle',
        CLEAR_ALLOWED_WEBSITES_MESSAGE: 'clearAllowedWebsitesMessage',
        CLEAR_ALLOWED_WEBSITES_CONTEXT: 'clearAllowedWebsitesContext',
        REPORT_WEBSITE_AS_MALICIOUS_CONTEXT: 'reportWebsiteAsMaliciousContext',

        WEBSITE_LINK: 'websiteLink',
        VERSION: 'version',
        PRIVACY_POLICY: 'privacyPolicy',
        STATUS_HEADING_SECURE: 'statusHeadingSecure',
        STATUS_HEADING_NO_PROVIDERS: 'statusHeadingNoProviders',
        STATUS_ICON_ALT_PROTECTED: 'statusIconAltProtected',
        PROVIDERS_ENABLED_COUNT: 'providersEnabledCount',
        OPEN_SETTINGS: 'openSettings',
        TERMS_LINK: 'termsLink',

        WARNING_TITLE: 'warningTitle',
        RECOMMENDATION: 'recommendation',
        DETAILS: 'details',
        REPORT_WEBSITE: 'reportWebsite',
        ALLOW_WEBSITE: 'allowWebsite',
        BACK_BUTTON: 'backButton',
        CONTINUE_BUTTON: 'continueButton',
        REPORTED_BY_OTHERS: 'reportedByOthers',
        REPORTED_BY_ALSO: 'reportedByAlso',
        UNKNOWN_ORIGIN: 'unknownOrigin',
        URL_UNAVAILABLE: 'urlUnavailable',
        CONTEXT_VERIFY_FAILED: 'contextVerifyFailed',

        KNOWN_SAFE: 'knownSafe',
        FAILED: 'failed',
        WAITING: 'waiting',
        ALLOWED: 'allowed',
        MALICIOUS: 'malicious',
        PHISHING: 'phishing',
        ADULT_CONTENT: 'adultContent',

        SETTINGS_TITLE: 'settingsTitle',
        PROVIDERS_SECTION: 'providersSection',
        THIRD_PARTY_SECTION: 'thirdPartySection',
        RESET_DEFAULT_PROVIDERS: 'resetDefaultProviders',
        RESET_ALL: 'resetAll',

        FIELD_LABEL_API_URL: 'fieldLabelApiUrl',
        FIELD_LABEL_API_KEY: 'fieldLabelApiKey',

        APPLY_BUTTON: 'applyButton',

        INDICATOR_ADULT_CONTENT: 'indicatorAdultContent',
        INDICATOR_IP_PROTECTED: 'indicatorIpProtected',
        OFFICIAL_PARTNER_TITLE: 'officialPartnerTitle',
        SHOW_API_KEY: 'showApiKey',
        HIDE_API_KEY: 'hideApiKey',

        TOAST_SAVED: 'toastSaved',
        TOAST_FAILED_TO_SAVE: 'toastFailedToSave',
        TOAST_DEFAULT_PROVIDERS_RESTORED: 'toastDefaultProvidersRestored',
        TOAST_ALL_SETTINGS_RESTORED: 'toastAllSettingsRestored',
        TOAST_SAVE_API_KEY_FIRST: 'toastSaveApiKeyFirst',
        TOAST_FAILED_TO_UPDATE_STATE: 'toastFailedToUpdateState',

        WARNING_PAGE_TITLE: 'unsafeWebsiteTitle',
        PROVIDER_NAME_FALLBACK: 'providerNameFallback',
    });

    const langUtil = Object.create(null);

    Object.defineProperties(langUtil, {
        ...Object.fromEntries(
            Object.entries(messageMap).map(([prop, key]) => [prop, {
                get: () => msg(key),
                enumerable: true,
            }])
        ),

        translate: {
            value: msg,
            enumerable: true,
        },

        format: {
            value: msg,
            enumerable: true,
        }
    });

    Object.freeze(langUtil);
    globalThis.LangUtil = langUtil;
})();
