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

globalThis.OspreyContextMenuService = (() => {
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const cacheService = globalThis.OspreyCacheService;
    const i18n = globalThis.OspreyI18n;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;
    const providerStateStore = globalThis.OspreyProviderStateStore;

    const menuIds = Object.freeze({
        TOGGLE_FRAME_NAVIGATION: 'toggleFrameNavigation',
        CLEAR_ALLOWED_WEBSITES: 'clearAllowedWebsites',
        REPORT_MALICIOUS: 'reportWebsiteAsMalicious',
    });

    let rebuildPromise = Promise.resolve();
    let clickListenerRegistered = false;

    const logError = message => error => {
        console.error(message, error);
    };

    const removeAll = () => browserAPI.withCallback(browserAPI.api?.contextMenus?.removeAll, browserAPI.api?.contextMenus).catch(() => undefined);

    const createItem = options => browserAPI.withCallback(browserAPI.api?.contextMenus?.create, browserAPI.api?.contextMenus, [options]).catch(error => {
        console.error(`Failed to create context menu item with id ${options.id}`, error);
        return undefined;
    });

    const doCreate = async () => {
        const runtime = await providerRuntimeFactory.createRuntime();
        const {app} = runtime.effectiveState;

        await removeAll();

        if (!app.contextMenuEnabled) {
            return;
        }

        await createItem({
            id: menuIds.TOGGLE_FRAME_NAVIGATION,
            title: i18n.translate('toggleFrameNavigationContext'),
            type: 'checkbox',
            checked: app.ignoreFrameNavigation,
            contexts: ['action'],
        });

        if (!app.disableClearAllowedWebsites) {
            await createItem({
                id: menuIds.CLEAR_ALLOWED_WEBSITES,
                title: i18n.translate('clearAllowedWebsitesContext'),
                contexts: ['action'],
            });
        }

        await createItem({
            id: menuIds.REPORT_MALICIOUS,
            title: i18n.translate('reportWebsiteAsMaliciousContext'),
            contexts: ['action'],
        });
    };

    const create = () => {
        rebuildPromise = rebuildPromise.catch(logError('Failed to rebuild context menus, skipping this rebuild to avoid potential infinite loop')).then(doCreate);
        return rebuildPromise;
    };

    const clearAllowedWebsites = () => cacheService.clearAll().then(() => browserAPI.notificationsCreate({
        type: 'basic',
        iconUrl: browserAPI.safeRuntimeURL('assets/osprey/icon128.png'),
        title: i18n.translate('clearAllowedWebsitesTitle'),
        message: i18n.translate('clearAllowedWebsitesMessage'),
        priority: 2,
    }));

    const clickHandlers = Object.freeze({
        [menuIds.TOGGLE_FRAME_NAVIGATION]: info => providerStateStore.setAppSettings({
            ignoreFrameNavigation: Boolean(info.checked)
        }).catch(logError('Failed to update ignoreFrameNavigation setting from context menu')),

        [menuIds.CLEAR_ALLOWED_WEBSITES]: () => clearAllowedWebsites().catch(logError('Failed to clear allowed websites from context menu')),

        [menuIds.REPORT_MALICIOUS]: () => browserAPI.tabsCreate({
            url: 'https://github.com/OspreyProject/Osprey/wiki/Report-Website-as-Malicious'
        }).catch(logError('Failed to open malicious website reporting documentation')),
    });

    const handleClick = info => {
        const handler = clickHandlers[info.menuItemId];

        if (!handler) {
            console.warn(`Clicked context menu item with unrecognized id: ${info.menuItemId}`);
            return;
        }

        handler(info);
    };

    const register = () => {
        if (clickListenerRegistered) {
            console.warn('Context menu click listener is already registered, skipping duplicate registration');
            return;
        }

        browserAPI.api?.contextMenus?.onClicked?.addListener(handleClick);
        clickListenerRegistered = true;
    };

    // Public API
    return Object.freeze({
        create,
        register
    });
})();
