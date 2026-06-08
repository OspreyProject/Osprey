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

globalThis.OspreyContextMenuService = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const cacheService = globalThis.OspreyCacheService;
    const providerRuntimeFactory = globalThis.OspreyProviderRuntimeFactory;

    const menuIds = {
        CLEAR_ALLOWED_WEBSITES: 'clearAllowedWebsites',
        REPORT_MALICIOUS: 'reportWebsiteAsMalicious',
    };

    const safeIconURL = browserAPI.safeRuntimeURL('assets/osprey/icon128.png');

    let isRebuilding = false;
    let pendingRebuild = false;
    let clickListenerRegistered = false;
    let lastMenuSignature = 0;

    const clearAllowedOptions = {
        id: menuIds.CLEAR_ALLOWED_WEBSITES,
        title: null,
        contexts: ['action'],
    };

    const reportMaliciousOptions = {
        id: menuIds.REPORT_MALICIOUS,
        title: null,
        contexts: ['action'],
    };

    const tabCreationOptions = {
        url: 'https://phish.report/analysis',
    };

    const notificationOptions = {
        type: 'basic',
        iconUrl: safeIconURL,
        title: null,
        message: null,
        priority: 2,
    };

    const logError = context => error => console.error(context, error);
    const logCreationError = logError('Failed to create context menu item');
    const logClearError = logError('Failed to clear allowed websites from context menu');
    const logPhishError = logError('Failed to open Phish.Report website');

    const swallowError = () => undefined;

    const removeAll = () => browserAPI.withCallback(browserAPI.api?.contextMenus?.removeAll, browserAPI.api?.contextMenus).catch(swallowError);

    const createItem = options => browserAPI.withCallback(browserAPI.api?.contextMenus?.create, browserAPI.api?.contextMenus, [options]).catch(logCreationError);

    const doCreate = async () => {
        try {
            isRebuilding = true;
            const runtime = await providerRuntimeFactory.createAppRuntime();
            const app = runtime.effectiveState.app;

            const enabledBit = app.contextMenuEnabled ? 1 : 0;
            const disabledBit = app.disableClearAllowedWebsites ? 1 : 0;
            const currentSignature = enabledBit << 1 | disabledBit;

            if (lastMenuSignature === currentSignature) {
                return;
            }

            await removeAll();

            if (enabledBit === 0) {
                lastMenuSignature = currentSignature;
                return;
            }

            const creationTasks = [];

            if (disabledBit === 0) {
                clearAllowedOptions.title = LangUtil.CLEAR_ALLOWED_WEBSITES_CONTEXT;
                creationTasks.push(createItem(clearAllowedOptions));
            }

            reportMaliciousOptions.title = LangUtil.REPORT_WEBSITE_AS_MALICIOUS_CONTEXT;
            creationTasks.push(createItem(reportMaliciousOptions));

            await Promise.all(creationTasks);
            lastMenuSignature = currentSignature;
        } catch (error) {
            console.error('Failed to rebuild context menus', error);
            lastMenuSignature = 0;
        } finally {
            isRebuilding = false;

            if (pendingRebuild) {
                pendingRebuild = false;
                doCreate().catch(swallowError);
            }
        }
    };

    const create = () => {
        if (isRebuilding) {
            pendingRebuild = true;
            return Promise.resolve();
        }
        return doCreate();
    };

    const clearAllowedWebsites = () => {
        return cacheService.clearAll().then(() => {
            notificationOptions.title = LangUtil.CLEAR_ALLOWED_WEBSITES_TITLE;
            notificationOptions.message = LangUtil.CLEAR_ALLOWED_WEBSITES_MESSAGE;
            return browserAPI.notificationsCreate(notificationOptions);
        });
    };

    const clickHandlers = {
        [menuIds.CLEAR_ALLOWED_WEBSITES]: () => clearAllowedWebsites().catch(logClearError),
        [menuIds.REPORT_MALICIOUS]: () => browserAPI.tabsCreate(tabCreationOptions).catch(logPhishError),
    };

    const handleClick = info => {
        const handler = clickHandlers[info.menuItemId];

        if (handler) {
            handler();
        } else {
            console.warn(`Clicked context menu item with unrecognized id: ${info.menuItemId}`);
        }
    };

    const register = () => {
        if (clickListenerRegistered) {
            console.warn('Context menu click listener is already registered, skipping duplicate registration');
            return;
        }

        browserAPI.api?.contextMenus?.onClicked?.addListener(handleClick);
        clickListenerRegistered = true;
    };

    return Object.freeze({
        create,
        register,
    });
})();
