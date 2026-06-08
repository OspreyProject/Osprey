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

globalThis.PopupSingleton = globalThis.PopupSingleton || (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerStateStore = globalThis.OspreyProviderStateStore;

    const termsURL = 'https://github.com/OspreyProject/Osprey/blob/main/.github/TERMS.md';
    const privacyURL = 'https://github.com/OspreyProject/Osprey/blob/main/.github/PRIVACY.md';
    let isInitialized = false;

    const setText = (element, value) => {
        if (element !== null) {
            element.textContent = value;
        }
    };

    const setLink = (element, text, href) => {
        if (element !== null) {
            element.textContent = text;
            element.href = href;
        }
    };

    const initialize = (state) => {
        if (isInitialized) {
            return;
        }

        isInitialized = true;

        const logo = document.getElementById('logo');
        const bannerText = document.querySelector('.bannerText');
        const statusIcon = document.getElementById('statusIcon');
        const statusHeading = document.getElementById('statusHeading');
        const providerCount = document.getElementById('providerCount');
        const settingsButton = document.getElementById('settingsButton');
        const websiteLink = document.getElementById('websiteLink');
        const version = document.getElementById('version');
        const privacyPolicy = document.getElementById('privacyPolicy');
        const termsFooterLink = document.getElementById('termsFooterLink');

        document.title = LangUtil.TITLE;
        setText(bannerText, LangUtil.TITLE);
        setText(websiteLink, LangUtil.WEBSITE_LINK);

        const manifestVersion = browserAPI.api?.runtime.getManifest().version || '';
        setText(version, LangUtil.VERSION + manifestVersion);

        setLink(privacyPolicy, LangUtil.PRIVACY_POLICY, privacyURL);
        setLink(termsFooterLink, LangUtil.TERMS_LINK, termsURL);

        LangUtil.applyLogoAlt(logo);

        if (settingsButton !== null) {
            settingsButton.textContent = LangUtil.OPEN_SETTINGS;
            settingsButton.onclick = onSettingsButtonClick;
        }

        const noProvidersText = LangUtil.STATUS_HEADING_NO_PROVIDERS;
        const enabledCount = providerStateStore.countEnabledProviders(state);
        const total = providerStateStore.countTotalProviders();
        const noProviders = enabledCount === 0;

        if (statusIcon !== null) {
            statusIcon.src = noProviders ? '../../assets/misc/warning.avif' : '../../assets/misc/checkmark.avif';
            statusIcon.alt = noProviders ? noProvidersText : LangUtil.STATUS_ICON_ALT_PROTECTED;
        }

        setText(statusHeading, noProviders ? noProvidersText : LangUtil.STATUS_HEADING_SECURE);

        const localizedTemplate = LangUtil.PROVIDERS_ENABLED_COUNT;
        const blankText = localizedTemplate.indexOf('___');

        if (blankText === -1) {
            setText(providerCount, localizedTemplate);
        } else {
            const textCount = localizedTemplate.slice(0, blankText) + enabledCount;
            const remainder = localizedTemplate.slice(blankText + 3);
            const blankRemainder = remainder.indexOf('___');

            if (blankRemainder === -1) {
                setText(providerCount, textCount + remainder);
            } else {
                setText(providerCount, textCount + remainder.slice(0, blankRemainder) + total + remainder.slice(blankRemainder + 3));
            }
        }
    };

    const onSettingsButtonClick = () => {
        browserAPI.runtimeOpenOptionsPage().catch(onSettingsError);
    };

    const onSettingsError = (error) => {
        console.error('PopupSingleton failed to open the settings page', error);
    };

    return Object.freeze({
        initialize: initialize
    });
})();

(() => {
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const policyService = globalThis.OspreyPolicyService;
    const popupSingleton = globalThis.PopupSingleton;

    const boot = () => {
        providerStateStore.getState()
            .then(state => policyService.applyToState(state))
            .then(result => processStateAndBoot(result.effectiveState))
            .catch(handleBootFallback);
    };

    const processStateAndBoot = (state) => {
        if (state !== null && typeof state === 'object' && state.app?.hidePopupPanel) {
            if (typeof globalThis.close === 'function') {
                globalThis.close();
            }
        } else if (popupSingleton) {
            popupSingleton.initialize(state);
        }
    };

    const handleBootFallback = (error) => {
        console.warn('PopupPage failed to load settings before initialization; continuing with fallback boot path', error);

        if (popupSingleton) {
            popupSingleton.initialize(null);
        }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot, {once: true});
    } else {
        boot();
    }
})();
