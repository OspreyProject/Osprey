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
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;

    const menuIds = Object.freeze({
        CLEAR_ALLOWED_WEBSITES: 'clearAllowedWebsites',
        REPORT_MALICIOUS: 'reportWebsiteAsMalicious',
    });

    const safeIconURL = browserAPI.safeRuntimeURL('assets/osprey/icon128.png');

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

        if (!app.disableClearAllowedWebsites) {
            await createItem({
                id: menuIds.CLEAR_ALLOWED_WEBSITES,
                title: LangUtil.CLEAR_ALLOWED_WEBSITES_CONTEXT,
                contexts: ['action'],
            });
        }

        await createItem({
            id: menuIds.REPORT_MALICIOUS,
            title: LangUtil.REPORT_WEBSITE_AS_MALICIOUS_CONTEXT,
            contexts: ['action'],
        });
    };

    const create = () => {
        rebuildPromise = rebuildPromise.catch(logError('Failed to rebuild context menus, skipping this rebuild to avoid potential infinite loop')).then(doCreate);
        return rebuildPromise;
    };

    const clearAllowedWebsites = () => cacheService.clearAll().then(() => browserAPI.notificationsCreate({
        type: 'basic',
        iconUrl: safeIconURL,
        title: LangUtil.CLEAR_ALLOWED_WEBSITES_TITLE,
        message: LangUtil.CLEAR_ALLOWED_WEBSITES_MESSAGE,
        priority: 2,
    }));

    const clickHandlers = Object.freeze({
        [menuIds.CLEAR_ALLOWED_WEBSITES]: () => clearAllowedWebsites().catch(logError('Failed to clear allowed websites from context menu')),

        [menuIds.REPORT_MALICIOUS]: () => browserAPI.tabsCreate({
            url: 'https://phish.report/analysis'
        }).catch(logError('Failed to open Phish.Report website')),
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
