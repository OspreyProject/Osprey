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

globalThis.SettingsSingleton = globalThis.SettingsSingleton || (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const providerList = globalThis.OspreyProviderList;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;

    let cachedExtensionVersion = null;
    let isInitialized = false;

    function setTextById(id, text) {
        const element = document.getElementById(id);

        if (element !== null) {
            element.textContent = text;
        }
    }

    function setTextBySelector(selector, text) {
        const element = document.querySelector(selector);

        if (element !== null) {
            element.textContent = text;
        }
    }

    function initFooter() {
        if (cachedExtensionVersion === null) {
            cachedExtensionVersion = browserAPI.api?.runtime.getManifest().version || '';
        }

        document.title = LangUtil.SETTINGS_TITLE;
        setTextById('version', LangUtil.VERSION + cachedExtensionVersion);
        setTextBySelector('.bannerText', LangUtil.TITLE);
    }

    const onRefreshError = error => {
        console.error('SettingsPage: failed to refresh state', error);
    };

    const onInitError = error => {
        console.error('SettingsPage: initialization failed', error);
    };

    const refresh = async () => {
        try {
            const runtime = await providerRuntimeFactory.createRuntime();
            providerList.render(runtime.effectiveState, runtime);
        } catch (error) {
            onRefreshError(error);
        }
    };

    function initialize() {
        if (isInitialized) {
            return;
        }

        isInitialized = true;
        document.addEventListener('osprey:settings-changed', refresh);

        refresh().then(initFooter).catch(onInitError);
    }

    function dispose() {
        if (!isInitialized) {
            return;
        }

        document.removeEventListener('osprey:settings-changed', refresh);
        isInitialized = false;
    }

    return Object.freeze({
        initialize,
        dispose,
    });
})();
