/*
 * Copyright (C) 2024-2026 Osprey Project LLC and contributors (https://osprey.ac)
 * SPDX-License-Identifier: GPL-3.0-or-later
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
    const formHelpers = globalThis.OspreyFormHelpers;
    const providerList = globalThis.OspreyProviderList;
    const exclusionsPage = globalThis.OspreyExclusionsPage;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;

    const defaultPage = 'providers';

    let cachedExtensionVersion = null;
    let isInitialized = false;
    let activePage = defaultPage;
    let currentRuntime = null;

    const navButtons = new Map();

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
        setTextById('version', cachedExtensionVersion);
        setTextBySelector('.bannerText', LangUtil.TITLE);

        const themeToggle = document.getElementById('themeToggle');

        if (themeToggle !== null) {
            themeToggle.setAttribute('aria-label', LangUtil.THEME_TOGGLE_LABEL);
            themeToggle.setAttribute('title', LangUtil.THEME_TOGGLE_LABEL);
        }
    }

    const navItems = () => [
        {
            page: 'providers',
            label: LangUtil.NAV_PROVIDERS
        },
        {
            page: 'exclusions',
            label: LangUtil.NAV_EXCLUSIONS
        },
    ];

    function buildNav() {
        const nav = document.getElementById('settingsNav');

        if (!nav || navButtons.size > 0) {
            return;
        }

        const items = navItems();

        for (let i = 0, len = items.length; i < len; i++) {
            const item = items[i];

            const button = formHelpers.createElement('button', {
                type: 'button',
                className: 'nav-item',
                textContent: item.label,
                dataset: {page: item.page},
                ariaPressed: item.page === activePage,
            });

            button.addEventListener('click', () => setActivePage(item.page));
            navButtons.set(item.page, button);
            nav.appendChild(button);
        }

        syncNavState();
    }

    function syncNavState() {
        for (const [page, button] of navButtons.entries()) {
            const isActive = page === activePage;
            button.classList.toggle('active', isActive);
            button.setAttribute('aria-pressed', String(isActive));
        }
    }

    function syncPageVisibility() {
        const pages = document.querySelectorAll('.settings-page');

        for (let i = 0, len = pages.length; i < len; i++) {
            const pageElement = pages[i];
            pageElement.hidden = pageElement.dataset.page !== activePage;
        }
    }

    function renderActivePage() {
        if (!currentRuntime) {
            return;
        }

        if (activePage === 'exclusions') {
            exclusionsPage?.render(currentRuntime).then(() => {
                // ignored
            });
        } else {
            providerList.render(currentRuntime.effectiveState, currentRuntime);
        }
    }

    function setActivePage(page) {
        if (!navButtons.has(page)) {
            return;
        }

        activePage = page;
        syncNavState();
        syncPageVisibility();
        renderActivePage();
    }

    const onRefreshError = error => {
        console.error('SettingsPage: failed to refresh state', error);
    };

    const onInitError = error => {
        console.error('SettingsPage: initialization failed', error);
    };

    const refresh = async () => {
        try {
            currentRuntime = await providerRuntimeFactory.createRuntime();
            renderActivePage();
        } catch (error) {
            onRefreshError(error);
        }
    };

    function initialize() {
        if (isInitialized) {
            return;
        }

        isInitialized = true;
        buildNav();
        syncPageVisibility();
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
