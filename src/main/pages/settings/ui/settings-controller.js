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

globalThis.SettingsSingleton = globalThis.SettingsSingleton || (() => {
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerList = globalThis.OspreyProviderList;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;

    let isInitialized = false;

    function setText(selector, text, method = 'querySelector') {
        const element = document[method](selector);

        if (element) {
            element.textContent = text;
        }
    }

    function initFooter() {
        setText('version', LangUtil.VERSION + browserAPI.api?.runtime.getManifest().version, 'getElementById');
        document.title = LangUtil.SETTINGS_TITLE;
        setText('.settings-page-title', LangUtil.SETTINGS_TITLE);
        setText('.bannerText', LangUtil.TITLE);
    }

    const refresh = async () => {
        try {
            const runtime = await providerRuntimeFactory.createRuntime();
            providerList.render(runtime.effectiveState, runtime);
        } catch (error) {
            console.error('SettingsPage: failed to refresh state', error);
        }
    };

    function initialize() {
        if (isInitialized) {
            return;
        }

        isInitialized = true;
        document.addEventListener('osprey:settings-changed', refresh);

        refresh().then(initFooter, error => {
            console.error('SettingsPage: initialization failed', error);
        });
    }

    // Public API
    return Object.freeze({
        initialize
    });
})();
