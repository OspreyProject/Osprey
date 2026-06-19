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

globalThis.WarningSingleton = globalThis.WarningSingleton || (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const messages = globalThis.OspreyMessageBus.Messages;
    const ports = globalThis.OspreyMessageBus.Ports;
    const protectionResult = globalThis.OspreyProtectionResult;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const policyService = globalThis.OspreyPolicyService;
    const reportLinkBuilder = globalThis.OspreyReportLinkBuilder;

    const safeTitleRegex = /[^\p{L}\p{N}\p{Z}\p{P}]/gu;

    let reportedByText = LangUtil.UNKNOWN_ORIGIN;
    let currentOrigin = protectionResult.Origin.UNKNOWN;
    let currentContext = null;
    let currentState = null;
    const domElements = {};

    let pageshowListenerRegistered = false;
    let counterPort = null;
    let actionInFlight = false;
    let isInitialized = false;
    let revealed = false;

    const revealPage = () => {
        if (revealed) {
            return;
        }

        revealed = true;
        document.documentElement.style.visibility = 'visible';
    };

    const domElementIDs = [
        'reason', 'url', 'reportedBy', 'reportWebsite', 'allowWebsite',
        'backButton', 'continueButton', 'warningTitle', 'recommendation',
        'details', 'urlLabel', 'reportedByLabel', 'reasonLabel', 'logo', 'reportBreakpoint',
    ];

    const warningContextFallback = {
        blockedUrl: '',
        origin: 'unknown',
        result: 'failed',
    };

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
            hideReportButton: true,
        },
        providers: {},
    };

    const withCurrentTabId = message => {
        message.tabId = typeof currentContext?.tabId === 'number' ? currentContext.tabId : message.tabId;
        return message;
    };

    const isExpectedPortClosureError = error => {
        if (!error) {
            return false;
        }

        const message = error.message || error;

        if (typeof message !== 'string') {
            return false;
        }

        return message.includes('The message port closed before a response was received') ||
            message.includes('A listener indicated an asynchronous response by returning true');
    };

    const sendNavigationMessage = async message => {
        try {
            return await browserAPI.runtimeSendMessage(message);
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
        if (element && element.textContent !== value) {
            element.textContent = value;
        }
    }

    const resetReportedBy = () => {
        const el = domElements.reportedBy;

        if (el) {
            setTextContent(el, reportedByText);

            if (el.title !== '') {
                el.title = '';
            }
        }
    };

    const syncPrimaryContext = (origin, result) => {
        currentContext = buildContext({...currentContext, origin, result});
        currentOrigin = currentContext.origin;
        showContext(currentContext);
        applyOriginVisuals(currentOrigin);
        syncActionVisibility();
    };

    function parseSafeHttpUrl(value) {
        if (!value) {
            return null;
        }

        const rawValue = typeof value === 'string' ? value.trim() : String(value).trim();
        const httpLength = 7;

        if (rawValue.length < httpLength) {
            return null;
        }

        if (!rawValue.startsWith('http:') && !rawValue.startsWith('https:')) {
            return null;
        }

        try {
            const parsed = new URL(rawValue);

            if (!parsed.hostname) {
                return null;
            }

            parsed.hash = '';
            return parsed;
        } catch {
            return null;
        }
    }

    function stripTrailingSlash(parsed) {
        return parsed.toString().replace(/\/+$/, '');
    }

    function buildContext(fields) {
        const result = protectionResult.normalize(fields.result);
        const origin = parseOriginParam(fields.origin);
        const blockedUrl = typeof fields.blockedUrl === 'string' && fields.blockedUrl.length > 0 ? fields.blockedUrl : null;
        const actionable = fields.actionable ?? Boolean(blockedUrl);
        const reportable = origin !== protectionResult.Origin.UNKNOWN;
        const resultTextEN = resultNameEnglish(result);

        let cachedReportUrl = null;

        if (blockedUrl && reportable) {
            const definition = providerCatalog.getDefinition(origin);

            if (definition?.report && definition.report.type !== 'none') {
                const rUrl = reportLinkBuilder.build(definition.report, {
                    blockedUrl,
                    resultLabelEnglish: resultTextEN,
                });

                cachedReportUrl = rUrl ? new URL(rUrl).toString() : null;
            }
        }

        return {
            result,
            resultText: resultName(result),
            resultTextEN,
            blockedUrl,
            origin,
            tabId: typeof fields.tabId === 'number' && Number.isFinite(fields.tabId) ? fields.tabId : null,
            actionable,
            reportable,
            cachedReportUrl,
        };
    }

    function resolveProviderName(id) {
        return typeof id === 'string' ? providerCatalog.getDefinition(id)?.displayName ?? id : LangUtil.UNKNOWN_ORIGIN;
    }

    function applyOriginVisuals(origin) {
        const systemName = typeof origin === 'string' ? resolveProviderName(origin) : LangUtil.UNKNOWN_ORIGIN;
        const el = domElements.reportedBy;

        if (el && el.textContent !== systemName) {
            el.textContent = systemName;
            reportedByText = systemName;
        }
    }

    function updateBlockedCounter(response) {
        const el = domElements.reportedBy;

        if (!el) {
            return;
        }

        const nextPrimaryOrigin = typeof response?.primaryOrigin === 'string' ? response.primaryOrigin : null;
        const nextPrimaryResult = typeof response?.primaryResult === 'string' ? protectionResult.normalize(response.primaryResult) : null;

        if (nextPrimaryOrigin && nextPrimaryResult && currentContext && nextPrimaryOrigin !== currentContext.origin && isKnownResult(nextPrimaryResult)) {
            syncPrimaryContext(nextPrimaryOrigin, nextPrimaryResult);
        }

        const count = response?.count;
        const systemsArr = response?.systems;

        if (typeof count !== 'number' || !Array.isArray(systemsArr) || count <= 0) {
            resetReportedBy();
            return;
        }

        const othersText = LangUtil.REPORTED_BY_OTHERS.replace('___', count.toString());
        let systemsStr = '';

        for (let i = 0, len = systemsArr.length; i < len; i++) {
            const name = resolveProviderName(String(systemsArr[i]));

            if (name) {
                if (systemsStr.length > 0) {
                    systemsStr += ', ';
                }

                systemsStr += name;
            }
        }

        setTextContent(el, `${reportedByText} ${othersText}`);

        const newTitle = `${LangUtil.REPORTED_BY_ALSO}${systemsStr}`.replace(safeTitleRegex, '');

        if (el.title !== newTitle) {
            el.title = newTitle;
        }
    }

    function handleCounterMessage(message) {
        if (message?.messageType !== messages.BLOCKED_COUNTER_PONG) {
            return;
        }

        if (typeof currentContext?.tabId === 'number' &&
            typeof message?.tabId === 'number' &&
            message.tabId !== currentContext.tabId) {
            return;
        }

        updateBlockedCounter(message);
    }

    function ensureCounterPort() {
        if (counterPort) {
            return counterPort;
        }

        const port = browserAPI.api?.runtime?.connect?.({name: ports.BLOCKED_COUNTER});

        if (!port) {
            return null;
        }

        counterPort = port;
        port.onMessage.addListener(handleCounterMessage);

        port.onDisconnect.addListener(() => {
            counterPort = null;
        });
        return port;
    }

    function refreshBlockedCounter() {
        const port = ensureCounterPort();

        if (!port) {
            resetReportedBy();
            return;
        }

        try {
            port.postMessage(withCurrentTabId({messageType: messages.BLOCKED_COUNTER_PING}));
        } catch (error) {
            counterPort = null;
            console.warn('WarningPage failed to refresh blocked-counter state', error);
            resetReportedBy();
        }
    }

    function disconnectCounterPort() {
        if (counterPort) {
            try {
                counterPort.disconnect();
            } catch {
                // ignored
            }

            counterPort = null;
        }
    }

    function syncCounterForVisibility() {
        if (document.visibilityState === 'visible') {
            refreshBlockedCounter();
        } else {
            disconnectCounterPort();
        }
    }

    function localizePage() {
        if (document.title !== LangUtil.WARNING_PAGE_TITLE) {
            document.title = LangUtil.WARNING_PAGE_TITLE;
        }

        setTextContent(document.querySelector('.bannerText'), LangUtil.TITLE);
        setTextContent(document.querySelector('.warning-page-title'), LangUtil.WARNING_PAGE_TITLE);

        for (let i = 0, len = domElementIDs.length; i < len; i++) {
            const id = domElementIDs[i];
            const value = pageTextByID[id];

            if (value) {
                setTextContent(domElements[id], value);
            }
        }

        LangUtil.applyLogoAlt(domElements.logo);
    }

    function parsePageContext(pageUrl) {
        const warningContext = extractWarningContext(pageUrl);
        const result = isKnownResult(warningContext.result) ? warningContext.result : protectionResult.resultTypes.FAILED;
        const blockedUrlParsed = parseSafeHttpUrl(warningContext.blockedUrl);

        return buildContext({
            blockedUrl: blockedUrlParsed ? stripTrailingSlash(blockedUrlParsed) : null,
            origin: warningContext.origin,
            result,
            actionable: blockedUrlParsed !== null,
            tabId: warningContext.tabId,
        });
    }

    const extractWarningContext = pageUrl => {
        try {
            let params;

            if (globalThis.window !== undefined && globalThis.location && globalThis.location.href === pageUrl) {
                params = new URLSearchParams(globalThis.location.search);
            } else {
                params = new URL(pageUrl).searchParams;
            }

            const rawTabId = params.get('tid');
            const parsedTabId = rawTabId ? Number.parseInt(rawTabId, 10) : Number.NaN;

            return {
                blockedUrl: params.get('url') || '',
                origin: params.get('or') || 'unknown',
                result: params.get('rs') || 'failed',
                tabId: Number.isFinite(parsedTabId) ? parsedTabId : null,
            };
        } catch {
            return warningContextFallback;
        }
    };

    function setElementVisibility(element, isVisible) {
        if (!element) {
            return;
        }

        const hidden = !isVisible;

        if (element.hidden !== hidden) {
            element.hidden = hidden;
        }

        if (element.classList.contains('hidden') !== hidden) {
            element.classList.toggle('hidden', hidden);
        }

        const ariaHidden = String(hidden);

        if (element.getAttribute('aria-hidden') !== ariaHidden) {
            element.setAttribute('aria-hidden', ariaHidden);
        }
    }

    function setButtonState(button, isVisible, isEnabled) {
        if (button) {
            setElementVisibility(button, isVisible);
            const disabled = !isEnabled;

            if (button.disabled !== disabled) {
                button.disabled = disabled;
            }
        }
    }

    function createActionHandler(handler) {
        return async event => {
            if (event?.preventDefault) {
                event.preventDefault();
            }

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

    function registerVisibilityListeners() {
        if (pageshowListenerRegistered) {
            return;
        }

        pageshowListenerRegistered = true;

        globalThis.addEventListener('pageshow', () => {
            applyOriginVisuals(currentOrigin);
            syncCounterForVisibility();
        });

        document.addEventListener('visibilitychange', syncCounterForVisibility);
    }

    function showContext(context) {
        setTextContent(domElements.reason, context.resultText);
        setTextContent(domElements.url, context.blockedUrl || LangUtil.URL_UNAVAILABLE);

        if (domElements.details) {
            setTextContent(domElements.details, context.actionable ? LangUtil.DETAILS : LangUtil.CONTEXT_VERIFY_FAILED);
        }
    }

    function syncActionVisibility() {
        if (!currentContext || !currentState) {
            return;
        }

        const appState = currentState.app;
        const canContinue = currentContext.actionable === true && !appState?.hideContinueButtons;

        const canReport = canContinue === true && currentContext.reportable === true &&
            !appState?.hideReportButton && currentContext.cachedReportUrl !== null;

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

        const systems = [];

        for (let i = 0, len = origins.length; i < len; i++) {
            if (origins[i] !== nextContext.primaryOrigin) {
                systems.push(origins[i]);
            }
        }

        updateBlockedCounter({
            count: Math.max(0, origins.length - 1),
            systems,
            primaryOrigin: nextContext.primaryOrigin,
            primaryResult: nextContext.primaryResult,
        });
    }

    function buildActionMessage(messageType) {
        return withCurrentTabId({
            messageType,
            blockedUrl: currentContext.blockedUrl,
            origin: currentContext.origin,
        });
    }

    function wireActions(state) {
        currentState = state;

        applyOriginVisuals(currentOrigin);
        syncCounterForVisibility();
        syncActionVisibility();

        const actionBindings = [
            [domElements.reportWebsite, async () => {
                const reportUrl = currentContext.cachedReportUrl;

                if (!reportUrl) {
                    console.warn('WarningPage could not resolve a report URL for the current warning context');
                    return;
                }
                await browserAPI.runtimeSendMessage(Object.assign(buildActionMessage(messages.REPORT_WEBSITE), {reportUrl}));
            }],

            [domElements.allowWebsite, () => sendNavigationMessage(buildActionMessage(messages.ALLOW_WEBSITE))],

            [domElements.continueButton, async () => {
                const response = await sendNavigationMessage(buildActionMessage(messages.CONTINUE_TO_WEBSITE));

                if (response?.context) {
                    applyNextBlockedContext(response.context);
                }
            }],

            [domElements.backButton, () => sendNavigationMessage(buildActionMessage(messages.CONTINUE_TO_SAFETY))],
        ];

        for (let i = 0, len = actionBindings.length; i < len; i++) {
            const button = actionBindings[i][0];
            const handler = actionBindings[i][1];

            if (button) {
                button.addEventListener('click', createActionHandler(handler));
            }
        }
    }

    function initialize() {
        if (isInitialized) {
            return;
        }

        isInitialized = true;

        for (let i = 0, len = domElementIDs.length; i < len; i++) {
            const id = domElementIDs[i];
            domElements[id] = document.getElementById(id);
        }

        currentContext = parsePageContext(document.URL);
        currentOrigin = currentContext.origin;

        localizePage();
        showContext(currentContext);
        registerVisibilityListeners();
        syncCounterForVisibility();

        providerStateStore.getState()
            .then(state => policyService.applyToAppState(state))
            .then(result => wireActions({app: result.effectiveApp}))
            .catch(error => {
                console.warn('WarningPage failed to resolve effective settings; applying fallback restrictions', error);
                wireActions(fallbackState);
            }).finally(revealPage);

        setTimeout(revealPage, 1000);
    }

    return {
        initialize,
    };
})();

(() => {
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => globalThis.WarningSingleton?.initialize?.(), {once: true});
    } else if (globalThis.WarningSingleton?.initialize) {
        globalThis.WarningSingleton.initialize();
    }
})();
