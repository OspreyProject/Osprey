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
'use strict';

(() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const i18n = browserAPI?.api?.i18n;

    const msg = (key, substitutions) => {
        if (!key || typeof key !== 'string') {
            return '';
        }

        try {
            if (substitutions !== undefined) {
                return i18n?.getMessage?.(key, substitutions) || key;
            }
            return i18n?.getMessage?.(key) || key;
        } catch (error) {
            console.error(`Error fetching translation for key "${key}":`, error);
            return key;
        }
    };

    const staticKeys = {
        TITLE: 'extensionName',
        LOGO_ALT: 'logoAlt',
        URL_LABEL: 'urlLabel',
        REPORTED_BY_LABEL: 'reportedByLabel',
        REASON_LABEL: 'reasonLabel',
        CLEAR_ALLOWED_WEBSITES_MESSAGE: 'clearAllowedWebsitesMessage',
        CLEAR_ALLOWED_WEBSITES: 'clearAllowedWebsites',
        REPORT_WEBSITE_AS_MALICIOUS: 'reportWebsiteAsMalicious',
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
        SETTINGS_TITLE: 'settingsTitle',
        PROVIDERS_SECTION: 'providersSection',
        THIRD_PARTY_SECTION: 'thirdPartySection',
        RESET_DEFAULT_PROVIDERS: 'resetDefaultProviders',
        RESET_ALL: 'resetAll',
        FIELD_LABEL_API_KEY: 'fieldLabelApiKey',
        BYPASS_BLOCKING_THRESHOLD: 'bypassBlockingThreshold',
        BYPASS_BLOCKING_THRESHOLD_TOOLTIP: 'bypassBlockingThresholdTooltip',
        APPLY_BUTTON: 'applyButton',
        INDICATOR_IP_PROTECTED: 'indicatorIpProtected',
        OFFICIAL_PARTNER_TITLE: 'officialPartnerTitle',
        SHOW_API_KEY: 'showApiKey',
        HIDE_API_KEY: 'hideApiKey',
        GET_API_KEY: 'getApiKey',
        TOAST_SAVED: 'toastSaved',
        TOAST_FAILED_TO_SAVE: 'toastFailedToSave',
        TOAST_DEFAULT_PROVIDERS_RESTORED: 'toastDefaultProvidersRestored',
        TOAST_ALL_SETTINGS_RESTORED: 'toastAllSettingsRestored',
        TOAST_SAVE_API_KEY_FIRST: 'toastSaveApiKeyFirst',
        TOAST_FAILED_TO_UPDATE_STATE: 'toastFailedToUpdateState',
        WARNING_PAGE_TITLE: 'warningPageTitle',
        PROVIDER_NAME_FALLBACK: 'providerNameFallback',
    };

    const resolvedKeys = {};
    const keys = Object.keys(staticKeys);

    for (const element of keys) {
        const prop = element;
        resolvedKeys[prop] = msg(staticKeys[prop]);
    }

    const langUtil = Object.freeze({
        translate: msg,
        format: msg,
        applyLogoAlt: element => {
            if (element) {
                element.alt = langUtil.LOGO_ALT;
            }
        },
        ...resolvedKeys,
    });

    globalThis.LangUtil = langUtil;
})();
