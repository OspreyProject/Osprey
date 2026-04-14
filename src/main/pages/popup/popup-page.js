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
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerStateStore = globalThis.OspreyProviderStateStore;

    const termsURL = 'https://github.com/OspreyProject/Osprey/blob/main/.github/TERMS.md';
    const privacyURL = 'https://github.com/OspreyProject/Osprey/blob/main/.github/PRIVACY.md';
    let isInitialized = false;

    const setText = (element, value) => element && (element.textContent = value);

    const setLink = (element, text, href) => {
        if (element) {
            element.textContent = text;
            element.href = href;
        }
    };

    const initialize = () => {
        if (isInitialized) {
            return;
        }

        isInitialized = true;

        const domElements = {
            logo: document.getElementById('logo'),
            bannerText: document.querySelector('.bannerText'),
            statusIcon: document.getElementById('statusIcon'),
            statusHeading: document.getElementById('statusHeading'),
            providerCount: document.getElementById('providerCount'),
            settingsButton: document.getElementById('settingsButton'),
            websiteLink: document.getElementById('websiteLink'),
            version: document.getElementById('version'),
            privacyPolicy: document.getElementById('privacyPolicy'),
            termsFooterLink: document.getElementById('termsFooterLink'),
        };

        const textBindings = [
            ['bannerText', LangUtil.TITLE],
            ['websiteLink', LangUtil.WEBSITE_LINK],
            ['version', LangUtil.VERSION + browserAPI.api?.runtime.getManifest().version],
        ];

        const noProvidersText = LangUtil.STATUS_HEADING_NO_PROVIDERS;

        document.title = LangUtil.TITLE;
        textBindings.forEach(([key, value]) => setText(domElements[key], value));
        setLink(domElements.privacyPolicy, LangUtil.PRIVACY_POLICY, privacyURL);
        setLink(domElements.termsFooterLink, LangUtil.TERMS_LINK, termsURL);

        if (domElements.logo) {
            domElements.logo.alt = LangUtil.LOGO_ALT;
        }

        if (domElements.settingsButton) {
            domElements.settingsButton.textContent = LangUtil.OPEN_SETTINGS;

            domElements.settingsButton.onclick = () => {
                browserAPI.runtimeOpenOptionsPage().catch(error => {
                    console.error('PopupSingleton failed to open the settings page', error);
                });
            };
        }

        providerStateStore.getState().then(state => {
            const enabledCount = providerStateStore.countEnabledProviders(state);
            const total = providerStateStore.countTotalProviders(state);
            const noProviders = enabledCount === 0;

            if (domElements.statusIcon) {
                domElements.statusIcon.src = noProviders ? '../../assets/misc/warning.avif' : '../../assets/misc/checkmark.avif';
                domElements.statusIcon.alt = noProviders ? noProvidersText : LangUtil.STATUS_ICON_ALT_PROTECTED;
            }

            setText(domElements.statusHeading, noProviders ? noProvidersText : LangUtil.STATUS_HEADING_SECURE);
            setText(domElements.providerCount, LangUtil.PROVIDERS_ENABLED_COUNT.replace('___', String(enabledCount)).replace('___', String(total)));
        }).catch(err => console.error('PopupPage: OspreyProviderStateStore.getState failed:', err));
    };

    // Public API
    return Object.freeze({
        initialize
    });
})();

(() => {
    // Global variables
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const popupSingleton = globalThis.PopupSingleton;

    const boot = () => {
        providerStateStore.getState()
            .then(state => !state || typeof state !== 'object' || state.app?.hidePopupPanel ? globalThis.close?.() : popupSingleton?.initialize?.())
            .catch(error => {
                console.warn('PopupPage failed to load settings before initialization; continuing with fallback boot path', error);
                popupSingleton?.initialize?.();
            });
    };

    // Defers initialization until DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', boot, {once: true});
    } else {
        boot();
    }
})();
