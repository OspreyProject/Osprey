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
        TOGGLE_FRAME_NAVIGATION_CONTEXT: 'toggleFrameNavigationContext',
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
        CUSTOM_PROVIDERS_SECTION: 'customProvidersSection',
        ADD_PROVIDER_TOGGLE: 'addProviderToggle',
        CANCEL_ADD_PROVIDER: 'cancelAddProvider',
        NEW_PROVIDER: 'newProvider',
        ADD_PROVIDER_BUTTON: 'addProviderButton',
        RESET_DEFAULT_PROVIDERS: 'resetDefaultProviders',
        RESET_ALL: 'resetAll',

        FIELD_LABEL_NAME: 'fieldLabelName',
        FIELD_LABEL_API_URL: 'fieldLabelApiUrl',
        FIELD_LABEL_METHOD: 'fieldLabelMethod',
        FIELD_LABEL_API_KEY: 'fieldLabelApiKey',
        FIELD_LABEL_REQUEST_HEADERS: 'fieldLabelRequestHeaders',
        FIELD_LABEL_REQUEST_BODY: 'fieldLabelRequestBody',
        FIELD_LABEL_BLOCK_LOGIC: 'fieldLabelBlockLogic',

        TAG_REQUEST_HEADERS_HINT: 'tagRequestHeadersHint',
        TAG_REQUEST_BODY_HINT: 'tagRequestBodyHint',
        TAG_BLOCK_LOGIC_HINT: 'tagBlockLogicHint',

        ADD_RULE_BUTTON: 'addRuleButton',
        LOGIC_IF_LABEL: 'logicIfLabel',
        LOGIC_RETURN_LABEL: 'logicReturnLabel',
        APPLY_BUTTON: 'applyButton',
        DELETE_BUTTON: 'deleteButton',

        INDICATOR_ADULT_CONTENT: 'indicatorAdultContent',
        INDICATOR_IP_PROTECTED: 'indicatorIpProtected',
        OFFICIAL_PARTNER_TITLE: 'officialPartnerTitle',
        SHOW_API_KEY: 'showApiKey',
        HIDE_API_KEY: 'hideApiKey',

        NO_CUSTOM_PROVIDERS: 'noCustomProviders',

        TOAST_SAVED: 'toastSaved',
        TOAST_FAILED_TO_SAVE: 'toastFailedToSave',
        TOAST_FAILED_TO_DELETE: 'toastFailedToDelete',
        TOAST_PROVIDER_ADDED: 'toastProviderAdded',
        TOAST_PROVIDER_DELETED: 'toastProviderDeleted',
        TOAST_DEFAULT_PROVIDERS_RESTORED: 'toastDefaultProvidersRestored',
        TOAST_ALL_SETTINGS_RESTORED: 'toastAllSettingsRestored',
        TOAST_SAVE_API_KEY_FIRST: 'toastSaveApiKeyFirst',
        TOAST_FAILED_TO_UPDATE_STATE: 'toastFailedToUpdateState',

        WARNING_PAGE_TITLE: 'unsafeWebsiteTitle',
        PROVIDER_LOGO_ALT: 'providerLogoAlt',
        PROVIDER_NAME_FALLBACK: 'providerNameFallback',
        TOAST_MAX_LOGIC_RULES: 'toastMaxLogicRules',
        TOAST_CANNOT_ENABLE_PROVIDER: 'toastCannotEnableProvider',
        ERROR_API_URL_REQUIRED: 'errorApiUrlRequired',
        ERROR_API_URL_INVALID: 'errorApiUrlInvalid',
        ERROR_API_URL_HTTPS: 'errorApiUrlHttps',
        ERROR_API_URL_PRIVATE: 'errorApiUrlPrivate',
        ERROR_API_URL_CREDENTIALS: 'errorApiUrlCredentials',
        ERROR_HEADERS_TOO_MANY: 'errorHeadersTooMany',
        ERROR_HEADER_FORMAT: 'errorHeaderFormat',
        ERROR_HEADER_INVALID_NAME: 'errorHeaderInvalidName',
        ERROR_HEADER_FORBIDDEN_NAME: 'errorHeaderForbiddenName',
        ERROR_REQUEST_BODY_INVALID_JSON: 'errorRequestBodyInvalidJson',
        ERROR_RULE_CONDITION_EMPTY: 'errorRuleConditionEmpty',
        ERROR_RULE_CONDITION_UNSUPPORTED: 'errorRuleConditionUnsupported',
        ERROR_RULE_CONDITION_RESPONSE_REF: 'errorRuleConditionResponseRef',
        ERROR_RULE_CONDITION_FORBIDDEN_TOKEN: 'errorRuleConditionForbiddenToken',
        ERROR_RULES_TOO_MANY: 'errorRulesTooMany',
        ERROR_PROVIDER_NAME_REQUIRED: 'errorProviderNameRequired',
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
        },

        resultLabel: {
            value(resultType) {
                return langUtil[String(resultType ?? '').toUpperCase()] || resultType;
            },
            enumerable: true,
        },
    });

    Object.freeze(langUtil);
    globalThis.LangUtil = langUtil;
})();
