/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2025 Foulest (https://github.com/Foulest)
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

// Browser API compatibility between Chrome and Firefox
const browserAPI = typeof browser === 'undefined' ? chrome : browser;

const LangUtil = {

    // Global
    TITLE: browserAPI.i18n.getMessage('title'),
    BANNER_TEXT: browserAPI.i18n.getMessage('bannerText'),
    LOGO_ALT: browserAPI.i18n.getMessage('logoAlt'),
    URL_LABEL: browserAPI.i18n.getMessage('urlLabel'),
    REPORTED_BY_LABEL: browserAPI.i18n.getMessage('reportedByLabel'),
    REASON_LABEL: browserAPI.i18n.getMessage('reasonLabel'),

    // Background
    UNSAFE_WEBSITE_TITLE: browserAPI.i18n.getMessage('unsafeWebsiteTitle'),
    CLEAR_ALLOWED_WEBSITES_TITLE: browserAPI.i18n.getMessage('clearAllowedWebsitesTitle'),
    CLEAR_ALLOWED_WEBSITES_MESSAGE: browserAPI.i18n.getMessage('clearAllowedWebsitesMessage'),
    RESTORE_DEFAULTS_TITLE: browserAPI.i18n.getMessage('restoreDefaultsTitle'),
    RESTORE_DEFAULTS_MESSAGE: browserAPI.i18n.getMessage('restoreDefaultsMessage'),
    TOGGLE_NOTIFICATIONS_CONTEXT: browserAPI.i18n.getMessage('toggleNotificationsContext'),
    TOGGLE_FRAME_NAVIGATION_CONTEXT: browserAPI.i18n.getMessage('toggleFrameNavigationContext'),
    CLEAR_ALLOWED_WEBSITES_CONTEXT: browserAPI.i18n.getMessage('clearAllowedWebsitesContext'),
    RESTORE_DEFAULTS_CONTEXT: browserAPI.i18n.getMessage('restoreDefaultsContext'),

    // Popup Page
    ON_TEXT: browserAPI.i18n.getMessage('onText'),
    OFF_TEXT: browserAPI.i18n.getMessage('offText'),
    ON_LOCKED_TEXT: browserAPI.i18n.getMessage('onLockedText'),
    OFF_LOCKED_TEXT: browserAPI.i18n.getMessage('offLockedText'),
    POPUP_TITLE: browserAPI.i18n.getMessage('popupTitle'),
    GITHUB_LINK: browserAPI.i18n.getMessage('githubLink'),
    VERSION: browserAPI.i18n.getMessage('version'),
    PRIVACY_POLICY: browserAPI.i18n.getMessage('privacyPolicy'),
    OFFICIAL_PARTNER_TITLE: browserAPI.i18n.getMessage('officialPartnerTitle'),

    // Warning Page
    WARNING_TITLE: browserAPI.i18n.getMessage('warningTitle'),
    RECOMMENDATION: browserAPI.i18n.getMessage('recommendation'),
    DETAILS: browserAPI.i18n.getMessage('details'),
    REPORT_WEBSITE: browserAPI.i18n.getMessage('reportWebsite'),
    ALLOW_WEBSITE: browserAPI.i18n.getMessage('allowWebsite'),
    BACK_BUTTON: browserAPI.i18n.getMessage('backButton'),
    CONTINUE_BUTTON: browserAPI.i18n.getMessage('continueButton'),
    REPORTED_BY_OTHERS: browserAPI.i18n.getMessage('reportedByOthers'),
    REPORTED_BY_ALSO: browserAPI.i18n.getMessage('reportedByAlso'),

    // Protection Result
    KNOWN_SAFE: browserAPI.i18n.getMessage('knownSafe'),
    FAILED: browserAPI.i18n.getMessage('failed'),
    WAITING: browserAPI.i18n.getMessage('waiting'),
    ALLOWED: browserAPI.i18n.getMessage('allowed'),
    MALICIOUS: browserAPI.i18n.getMessage('malicious'),
    PHISHING: browserAPI.i18n.getMessage('phishing'),
    UNTRUSTED: browserAPI.i18n.getMessage('untrusted'),
    ADULT_CONTENT: browserAPI.i18n.getMessage('adultContent'),
};
