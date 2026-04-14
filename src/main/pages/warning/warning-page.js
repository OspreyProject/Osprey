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

globalThis.WarningSingleton = globalThis.WarningSingleton || (() => {
    // Global variables
    const browserAPI = globalThis.OspreyBrowserAPI;
    const messages = globalThis.OspreyMessageBus.Messages;
    const protectionResult = globalThis.OspreyProtectionResult;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const reportLinkBuilder = globalThis.OspreyReportLinkBuilder;
    const urlService = globalThis.OspreyUrlService;

    let currentOrigin = protectionResult.Origin.UNKNOWN;
    let reportedByText = LangUtil.UNKNOWN_ORIGIN;
    let currentContext = null;
    let currentState = null;
    let domElements = {};
    let pageshowListenerRegistered = false;
    let runtimeListenerRegistered = false;
    let actionInFlight = false;
    let isInitialized = false;
    let providerNameMap = null;

    const domElementIDs = [
        'reason', 'url', 'reportedBy', 'reportWebsite', 'allowWebsite',
        'backButton', 'continueButton', 'warningTitle', 'recommendation',
        'details', 'urlLabel', 'reportedByLabel', 'reasonLabel', 'logo', 'reportBreakpoint',
    ];

    const pageTextByID = {
        warningTitle: LangUtil.WARNING_TITLE,
        recommendation: LangUtil.RECOMMENDATION,
        details: LangUtil.DETAILS,
        urlLabel: LangUtil.URL_LABEL,
        reportedByLabel: LangUtil.REPORTED_BY_LABEL,
        reasonLabel: LangUtil.REASON_LABEL,
        reportWebsite: LangUtil.REPORT_WEBSITE,
        allowWebsite: LangUtil.ALLOW_WEBSITE,
        backButton: LangUtil.BACK_BUTTON,
        continueButton: LangUtil.CONTINUE_BUTTON,
    };

    const fallbackState = {
        app: {
            hideContinueButtons: true,
            hideReportButton: true
        },
        providers: {},
        customProviders: {},
    };

    const sendRuntimeMessage = message => browserAPI.runtimeSendMessage(message);
    const withCurrentTabId = message => ({
        ...message,
        tabId: typeof currentContext?.tabId === 'number' ? currentContext.tabId : message?.tabId,
    });
    const isExpectedPortClosureError = error => {
        const message = String(error?.message || error || '');
        return message.includes('The message port closed before a response was received') ||
            message.includes('A listener indicated an asynchronous response by returning true, but the message channel closed before a response was received');
    };
    const sendRuntimeMessageForNavigatingAction = async message => {
        try {
            return await sendRuntimeMessage(message);
        } catch (error) {
            if (isExpectedPortClosureError(error)) {
                return {ok: true, navigated: true, disconnected: true};
            }

            throw error;
        }
    };
    const resultName = result => LangUtil[String(protectionResult.normalize(result) || protectionResult.resultTypes.FAILED).toUpperCase()] || LangUtil.FAILED;
    const resultNameEnglish = result => protectionResult.messageKeys[protectionResult.normalize(result)] || 'failed';
    const isKnownResult = result => Boolean(protectionResult.messageKeys[protectionResult.normalize(result)]);
    const parseOriginParam = raw => typeof raw === 'string' && /^[A-Za-z0-9_-]+$/.test(raw) ? raw : protectionResult.Origin.UNKNOWN;

    function setTextContent(element, value) {
        if (element) {
            element.textContent = value;
        }
    }

    const resetReportedBy = () => {
        if (!domElements.reportedBy) {
            return;
        }

        domElements.reportedBy.textContent = reportedByText;
        domElements.reportedBy.title = '';
    };

    const syncPrimaryContext = (origin, result) => {
        currentContext = buildContext({...currentContext, origin, result});
        currentOrigin = currentContext.origin;
        showContext(currentContext);
        applyOriginVisuals(currentOrigin);
        syncActionVisibility();
    };

    function parseSafeHttpUrl(value) {
        const rawValue = String(value ?? '').trim();

        if (!rawValue) {
            return null;
        }

        try {
            const parsed = new URL(rawValue);

            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:' || !parsed.hostname) {
                return null;
            }

            parsed.hash = '';
            return parsed;
        } catch {
            return null;
        }
    }

    function buildContext(fields = {}) {
        const result = protectionResult.normalize(fields.result);
        const origin = parseOriginParam(fields.origin);
        const blockedUrl = typeof fields.blockedUrl === 'string' && fields.blockedUrl.length > 0 ? fields.blockedUrl : null;
        const continueUrl = typeof fields.continueUrl === 'string' && fields.continueUrl.length > 0 ? fields.continueUrl : null;

        return Object.freeze({
            result,
            resultText: resultName(result),
            resultTextEN: resultNameEnglish(result),
            blockedUrl,
            continueUrl,
            origin,
            tabId: typeof fields.tabId === 'number' && Number.isFinite(fields.tabId) ? fields.tabId : null,
            actionable: fields.actionable ?? Boolean(blockedUrl),
            continueMatchesBlocked: fields.continueMatchesBlocked ?? true,
            reportable: origin !== protectionResult.Origin.UNKNOWN,
        });
    }

    function resolveProviderName(id) {
        if (typeof id !== 'string') {
            return LangUtil.UNKNOWN_ORIGIN;
        }

        const customDefinition = currentState?.customProviders?.[id];

        return providerNameMap?.get(id) ??
            customDefinition?.displayName ??
            providerCatalog.getDefinition(id, currentState)?.displayName ??
            id;
    }

    function applyOriginVisuals(origin) {
        const systemName = typeof origin === 'string' ? resolveProviderName(origin) : LangUtil.UNKNOWN_ORIGIN;

        if (domElements.reportedBy) {
            domElements.reportedBy.textContent = systemName;
            reportedByText = domElements.reportedBy.textContent;
        }
    }

    function updateBlockedCounter(response) {
        if (!domElements.reportedBy) {
            return;
        }

        const nextPrimaryOrigin = typeof response?.primaryOrigin === 'string' ? response.primaryOrigin : null;
        const nextPrimaryResult = typeof response?.primaryResult === 'string' ?
            protectionResult.normalize(response.primaryResult) : null;

        if (nextPrimaryOrigin && nextPrimaryResult && currentContext && nextPrimaryOrigin !== currentContext.origin &&
            isKnownResult(nextPrimaryResult)) {
            syncPrimaryContext(nextPrimaryOrigin, nextPrimaryResult);
        }

        if (typeof response?.count !== 'number' || !Array.isArray(response?.systems) || response.count <= 0) {
            resetReportedBy();
            return;
        }

        const othersText = LangUtil.REPORTED_BY_OTHERS.replace('___', response.count.toString());
        const systems = response.systems.map(system => resolveProviderName(String(system))).filter(Boolean);

        domElements.reportedBy.textContent = `${reportedByText} ${othersText}`;
        domElements.reportedBy.title = `${LangUtil.REPORTED_BY_ALSO}${systems.join(', ')}`
            .replaceAll(/[^\p{L}\p{N}\p{Z}\p{P}]/gu, '');
    }

    function refreshBlockedCounter() {
        return sendRuntimeMessage(withCurrentTabId({messageType: messages.BLOCKED_COUNTER_PING}))
            .then(updateBlockedCounter)
            .catch(error => {
                console.warn('WarningPage failed to refresh blocked-counter state', error);
                resetReportedBy();
            });
    }

    function localizePage() {
        document.title = LangUtil.WARNING_PAGE_TITLE;
        setTextContent(document.querySelector('.bannerText'), LangUtil.TITLE);
        setTextContent(document.querySelector('.warning-page-title'), LangUtil.WARNING_PAGE_TITLE);

        for (const [id, value] of Object.entries(pageTextByID)) {
            setTextContent(domElements[id], value);
        }

        if (domElements.logo) {
            domElements.logo.alt = LangUtil.LOGO_ALT;
        }
    }

    function parsePageContext(pageUrl) {
        const warningContext = urlService.extractWarningContext(pageUrl);
        const result = isKnownResult(warningContext.result) ? warningContext.result : protectionResult.resultTypes.FAILED;
        const blockedUrlParsed = parseSafeHttpUrl(warningContext.blockedUrl);
        const continueUrlParsed = parseSafeHttpUrl(warningContext.continueUrl);

        return buildContext({
            blockedUrl: blockedUrlParsed?.toString() ?? null,
            continueUrl: continueUrlParsed?.toString() ?? null,
            origin: warningContext.origin,
            result,
            actionable: Boolean(blockedUrlParsed),
            continueMatchesBlocked: blockedUrlParsed && continueUrlParsed ? continueUrlParsed.toString() === blockedUrlParsed.toString() : true,
            tabId: warningContext.tabId,
        });
    }

    function setElementVisibility(element, isVisible) {
        if (!element) {
            return;
        }

        element.hidden = !isVisible;
        element.classList.toggle('hidden', !isVisible);
        element.setAttribute('aria-hidden', String(!isVisible));
    }

    function setButtonState(button, isVisible, isEnabled) {
        if (button) {
            setElementVisibility(button, isVisible);
            button.disabled = !isEnabled;
        }
    }

    function createActionHandler(handler) {
        return async event => {
            event?.preventDefault?.();

            if (actionInFlight) {
                return;
            }

            actionInFlight = true;

            try {
                await handler();
            } catch (error) {
                if (!isExpectedPortClosureError(error)) {
                    console.error('WarningPage action failed', error);
                }
            } finally {
                actionInFlight = false;
            }
        };
    }

    function registerPageshowListener() {
        if (pageshowListenerRegistered) {
            return;
        }

        pageshowListenerRegistered = true;

        globalThis.addEventListener('pageshow', () => {
            applyOriginVisuals(currentOrigin);
            refreshBlockedCounter().catch(() => {
            });
        });
    }

    function registerRuntimeListener() {
        if (runtimeListenerRegistered) {
            return;
        }

        runtimeListenerRegistered = true;

        browserAPI.api?.runtime?.onMessage?.addListener(message => {
            if (!message || message.messageType !== messages.BLOCKED_COUNTER_PONG) {
                return false;
            }

            if (typeof currentContext?.tabId === 'number' && typeof message?.tabId === 'number' && message.tabId !== currentContext.tabId) {
                return false;
            }

            updateBlockedCounter(message);
            return true;
        });
    }

    function getReportUrl(context) {
        try {
            if (!context?.blockedUrl) {
                return null;
            }

            const definition = currentState?.customProviders?.[context.origin] ||
                providerCatalog.getDefinition(context.origin, currentState);

            if (!definition?.report || definition.report.type === 'none') {
                return null;
            }

            const url = reportLinkBuilder.build(definition.report, {
                blockedUrl: context.blockedUrl,
                resultLabelEnglish: context.resultTextEN,
            });
            return url ? new URL(url).toString() : null;
        } catch (error) {
            console.error('Failed to construct report URL:', error);
            return null;
        }
    }

    function showContext(context) {
        setTextContent(domElements.reason, context.resultText);
        setTextContent(domElements.url, context.blockedUrl ?? LangUtil.URL_UNAVAILABLE);

        if (domElements.details) {
            domElements.details.textContent = !context.actionable || !context.continueMatchesBlocked ?
                LangUtil.CONTEXT_VERIFY_FAILED :
                LangUtil.DETAILS;
        }
    }

    function syncActionVisibility() {
        if (!currentContext || !currentState) {
            return;
        }

        const canContinue = Boolean(
            currentContext.actionable &&
            currentContext.continueMatchesBlocked &&
            !currentState.app?.hideContinueButtons
        );

        const canReport = Boolean(
            canContinue &&
            currentContext.reportable &&
            !currentState.app?.hideReportButton &&
            getReportUrl(currentContext)
        );

        setButtonState(domElements.reportWebsite, canReport, canReport);
        setButtonState(domElements.allowWebsite, canContinue, canContinue);
        setButtonState(domElements.continueButton, canContinue, canContinue);
        setButtonState(domElements.backButton, true, true);
        setElementVisibility(domElements.reportBreakpoint, canReport && canContinue);
    }

    function applyNextBlockedContext(nextContext) {
        if (!nextContext || typeof nextContext.primaryOrigin !== 'string' || !isKnownResult(nextContext.primaryResult)) {
            return;
        }

        const origins = Array.isArray(nextContext.origins) ? nextContext.origins : [];
        syncPrimaryContext(nextContext.primaryOrigin, nextContext.primaryResult);

        updateBlockedCounter({
            count: Math.max(0, origins.length - 1),
            systems: origins.filter(origin => origin !== nextContext.primaryOrigin),
            primaryOrigin: nextContext.primaryOrigin,
            primaryResult: nextContext.primaryResult,
        });
    }

    function buildActionMessage(messageType) {
        return withCurrentTabId({
            messageType,
            blockedUrl: currentContext.blockedUrl,
            origin: currentContext.origin,
            continueUrl: currentContext.continueUrl,
        });
    }

    function wireActions(state) {
        currentState = state;
        providerNameMap = new Map(providerCatalog.getAllDefinitions(state).map(def => [def.id, def.displayName]));

        applyOriginVisuals(currentOrigin);
        refreshBlockedCounter().catch(() => {
        });
        syncActionVisibility();

        const actionBindings = [
            [domElements.reportWebsite, async () => {
                const reportUrl = getReportUrl(currentContext);

                if (!reportUrl) {
                    console.warn('WarningPage could not resolve a report URL for the current warning context');
                    return;
                }

                await sendRuntimeMessage({...buildActionMessage(messages.REPORT_WEBSITE), reportUrl});
            }],

            [domElements.allowWebsite, () => sendRuntimeMessageForNavigatingAction(buildActionMessage(messages.ALLOW_WEBSITE))],

            [domElements.continueButton, async () => {
                const response = await sendRuntimeMessageForNavigatingAction(buildActionMessage(messages.CONTINUE_TO_WEBSITE));

                if (response?.context) {
                    applyNextBlockedContext(response.context);
                }
            }],

            [domElements.backButton, () => sendRuntimeMessageForNavigatingAction(buildActionMessage(messages.CONTINUE_TO_SAFETY))],
        ];

        for (const [button, handler] of actionBindings) {
            button?.addEventListener('click', createActionHandler(handler));
        }
    }

    function initialize() {
        if (isInitialized) {
            return;
        }

        isInitialized = true;

        domElements = Object.fromEntries(domElementIDs.map(id => [id, document.getElementById(id)]));
        currentContext = parsePageContext(document.URL);
        currentOrigin = currentContext.origin;

        localizePage();
        showContext(currentContext);
        registerPageshowListener();
        registerRuntimeListener();

        providerStateStore.getState().then(wireActions).catch(error => {
            console.warn('WarningPage failed to load stored settings; applying fallback restrictions', error);
            wireActions(fallbackState);
        });
    }

    // Public API
    return Object.freeze({
        initialize
    });
})();

(() => {
    // Defers initialization until DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => globalThis.WarningSingleton?.initialize?.(), {once: true});
    } else {
        globalThis.WarningSingleton?.initialize?.();
    }
})();
