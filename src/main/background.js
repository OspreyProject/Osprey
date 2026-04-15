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

const bootstrapScripts = [
    'shared/browser-api.js',
    'shared/i18n.js',
    'shared/timed-signal.js',
    'providers/provider-groups.js',
    'providers/proxy-builtins.js',
    'providers/direct-integrations.js',
    'catalog/catalog-validator.js',
    'platform/protection-result.js',
    'platform/url-service.js',
    'platform/report-link-builder.js',
    'providers/custom-provider-normalizer.js',
    'providers/provider-catalog.js',
    'state/provider-state-store.js',
    'state/policy-service.js',
    'platform/request-builder.js',
    'platform/response-rule-engine.js',
    'state/cache-service.js',
    'platform/message-bus.js',
    'providers/provider-runtime-factory.js',
    'platform/dns-validator.js',
    'providers/provider-engine.js',
    'background/result-aggregation-service.js',
    'background/badge-service.js',
    'background/blocking-service.js',
    'background/navigation-service.js',
    'background/context-menu-service.js',
];

try {
    importScripts(...bootstrapScripts);
} catch (error) {
    // In Firefox-based browsers, importScripts is not available; scripts are loaded via background.html
    console.debug("Running in Firefox or another environment without importScripts");
    console.debug(`Error: ${error}`);
}

(() => {
    // Global variables
    const blockingService = globalThis.OspreyBlockingService;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const cacheService = globalThis.OspreyCacheService;
    const contextMenuService = globalThis.OspreyContextMenuService;
    const i18n = globalThis.OspreyI18n;
    const messages = globalThis.OspreyMessageBus.Messages;
    const navigationService = globalThis.OspreyNavigationService;
    const protectionResult = globalThis.OspreyProtectionResult;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerEngine = globalThis.OspreyProviderEngine;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const reportLinkBuilder = globalThis.OspreyReportLinkBuilder;
    const resultAggregationService = globalThis.OspreyResultAggregationService;

    const emptyBlockedCounterResponse = Object.freeze({
        count: 0,
        systems: [],
        primaryOrigin: null,
        primaryResult: null
    });

    const getMenuRelevantAppState = stateValue => ({
        contextMenuEnabled: Boolean(stateValue?.app?.contextMenuEnabled),
        ignoreFrameNavigation: Boolean(stateValue?.app?.ignoreFrameNavigation),
        disableClearAllowedWebsites: Boolean(stateValue?.app?.disableClearAllowedWebsites),
    });

    const respond = (sendResponse, payload) => {
        sendResponse?.(payload);
        return false;
    };

    const refreshContextMenus = errorMessage => contextMenuService.create().catch(error => {
        console.error(errorMessage, error);
    });

    const buildBlockedCounterResponse = tabId => {
        const context = resultAggregationService.getBlockedContext(tabId);

        if (!context) {
            return emptyBlockedCounterResponse;
        }

        const systems = context.origins.filter(origin => origin !== context.primaryOrigin);

        return {
            count: systems.length,
            systems,
            primaryOrigin: context.primaryOrigin,
            primaryResult: context.primaryResult
        };
    };

    const openReportUrlForOrigin = async ({origin, blockedUrl, result}) => {
        const definition = providerCatalog.getDefinition(origin, await providerStateStore.getState());

        if (!definition) {
            console.warn(`No provider definition found for origin ${origin} when building report URL`);
            return null;
        }

        return reportLinkBuilder.build(definition.report, {
            blockedUrl,
            resultLabelEnglish: i18n.translate(protectionResult.messageKeys[protectionResult.normalize(result)] || 'failed'),
        });
    };

    const didMenuRelevantAppStateChange = (previousStateValue, nextStateValue) => {
        const previousApp = getMenuRelevantAppState(previousStateValue);
        const nextApp = getMenuRelevantAppState(nextStateValue);

        return previousApp.contextMenuEnabled !== nextApp.contextMenuEnabled ||
            previousApp.ignoreFrameNavigation !== nextApp.ignoreFrameNavigation ||
            previousApp.disableClearAllowedWebsites !== nextApp.disableClearAllowedWebsites;
    };

    const respondAsync = (sendResponse, promise, errorMessage) => {
        promise.then(response => {
            sendResponse?.(response || {
                ok: true
            });
        }).catch(error => {
            console.error(errorMessage, error);
            sendResponse?.({
                ok: false
            });
        });
        return true;
    };

    const withTabId = (tabId, warningMessage, sendResponse, callback) => {
        if (typeof tabId === 'number') {
            callback(tabId);
        } else {
            console.warn(warningMessage);
            respond(sendResponse, {
                ok: false
            });
        }
    };

    const messageHandlers = {
        [messages.BLOCKED_COUNTER_PING]: ({tabId, sendResponse}) => {
            respond(sendResponse, typeof tabId === 'number' ? buildBlockedCounterResponse(tabId) : emptyBlockedCounterResponse);
        },

        [messages.CONTINUE_TO_SAFETY]: ({tabId, sendResponse}) => {
            withTabId(
                tabId,
                'OspreyBackground rejected CONTINUE_TO_SAFETY because the sender had no tab id',
                sendResponse,
                validTabId => respondAsync(
                    sendResponse,
                    blockingService.sendToSafety(validTabId).then(() => ({ok: true})),
                    `Failed CONTINUE_TO_SAFETY for tab ${validTabId}`
                )
            );
        },

        [messages.CONTINUE_TO_WEBSITE]: ({message, tabId, sendResponse}) => {
            if (typeof message.continueUrl !== 'string') {
                console.warn('OspreyBackground rejected CONTINUE_TO_WEBSITE because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            return withTabId(
                tabId,
                'OspreyBackground rejected CONTINUE_TO_WEBSITE because the sender had no tab id',
                sendResponse,
                validTabId => respondAsync(
                    sendResponse,
                    blockingService.continueToWebsite(validTabId, message.blockedUrl || message.continueUrl, message.origin, message.continueUrl),
                    `Failed CONTINUE_TO_WEBSITE for tab ${validTabId} and URL ${message.continueUrl}`
                )
            );
        },

        [messages.ALLOW_WEBSITE]: ({message, tabId, sendResponse}) => {
            if (typeof message.blockedUrl !== 'string') {
                console.warn('OspreyBackground rejected ALLOW_WEBSITE because the message payload was incomplete');
                return respond(sendResponse, {ok: false});
            }

            return withTabId(
                tabId,
                'OspreyBackground rejected ALLOW_WEBSITE because the sender had no tab id',
                sendResponse,
                validTabId => respondAsync(
                    sendResponse,
                    blockingService.allowWebsite(validTabId, message.blockedUrl, message.continueUrl || message.blockedUrl),
                    `Failed ALLOW_WEBSITE for tab ${validTabId}`
                )
            );
        },

        [messages.REPORT_WEBSITE]: ({message, tabId, sendResponse}) => {
            if (typeof message.reportUrl === 'string') {
                return respondAsync(sendResponse, blockingService.reportWebsite(message.reportUrl), `Failed REPORT_WEBSITE for tab ${tabId}`);
            }

            if (typeof message.origin === 'string' && typeof message.blockedUrl === 'string') {
                return respondAsync(
                    sendResponse,
                    openReportUrlForOrigin({
                        origin: message.origin,
                        blockedUrl: message.blockedUrl,
                        result: message.result
                    }).then(reportUrl => reportUrl ? blockingService.reportWebsite(reportUrl) : {ok: false}),
                    `Failed REPORT_WEBSITE for tab ${tabId}`
                );
            }

            console.warn('OspreyBackground rejected REPORT_WEBSITE because the message payload was incomplete');
            return respond(sendResponse, {ok: false});
        },
    };

    const handleMessage = (message, sender, sendResponse) => {
        if (!message || sender?.id !== browserAPI.api?.runtime.id) {
            console.warn(`No message for ${message?.id} for ${sender?.id}`);
            return false;
        }

        const handler = messageHandlers[message.messageType];

        if (!handler) {
            console.warn(`No message for ${message?.id}`);
            return false;
        }
        const messageTabId = typeof message?.tabId === 'number' ? message.tabId : null;
        return handler({message, sender, sendResponse, tabId: sender.tab?.id ?? messageTabId});
    };

    const init = async () => {
        try {
            browserAPI.api?.runtime.setUninstallURL?.('https://osprey.ac/uninstall');
        } catch {
            console.error('Failed to set uninstall URL, browser API may not be available');
        }

        browserAPI.api?.runtime.onMessage.addListener(handleMessage);

        browserAPI.api?.tabs.onRemoved?.addListener(tabId => {
            resultAggregationService.clear(tabId);
            providerEngine.abortTab(tabId);
            cacheService.clearProcessingByTab(tabId);
        });

        browserAPI.api?.storage.onChanged?.addListener((changes, area) => {
            if (area === 'managed') {
                refreshContextMenus('Failed to update context menus after managed storage change');
                return;
            }

            if (area !== 'local') {
                return;
            }

            const stateChange = changes?.[providerStateStore.stateKey];

            if (!stateChange || !didMenuRelevantAppStateChange(stateChange.oldValue, stateChange.newValue)) {
                return;
            }

            refreshContextMenus('Failed to update context menus after provider state change');
        });

        navigationService.register();
        contextMenuService.register();

        await contextMenuService.create().catch(error => {
            console.error('Failed to create context menus on initialization', error);
        });
    };

    init().catch(error => {
        console.error('Background init failed', error);
    });
})();
