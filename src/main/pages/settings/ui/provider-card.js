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

globalThis.OspreyProviderCard = (() => {
    // Global variables
    const formHelpers = globalThis.OspreyFormHelpers;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const toast = globalThis.OspreyToast;

    const createDiv = (className, ...children) => formHelpers.createElement('div', {className}, ...children);

    const createFallbackLogo = () => formHelpers.createElement('span', {
        className: 'provider-logo-fallback',
        attributes: {
            'aria-hidden': 'true'
        }
    });

    function setActionButtonState(button, isActive, activeClassName) {
        button.disabled = !isActive;
        button.classList.toggle(activeClassName, isActive);
    }

    function createProviderLogo(name, logoUrl) {
        const safeName = formHelpers.normalizeProviderName(name) || LangUtil.PROVIDER_NAME_FALLBACK;
        const source = String(logoUrl ?? '').trim();

        if (!source) {
            return createFallbackLogo();
        }

        try {
            const parsed = new URL(source, document.baseURI);
            const ok = ['chrome-extension:', 'moz-extension:', 'https:', 'data:'].includes(parsed.protocol);

            if (!ok) {
                throw new Error('Unsupported logo protocol');
            }

            return formHelpers.createElement('img', {
                className: 'provider-logo',
                src: parsed.toString(),
                alt: LangUtil.format('providerLogoAlt', safeName),
                attributes: {
                    loading: 'lazy',
                    decoding: 'async',
                    referrerpolicy: 'no-referrer'
                },
            });
        } catch {
            return createFallbackLogo();
        }
    }

    function createIndicator(className, label, tooltip) {
        return formHelpers.createElement('span', {
            className,
            role: 'img',
            tabIndex: 0,
            ariaLabel: label,
            attributes: {
                'data-tooltip': tooltip
            },
        });
    }

    function buildIndicators(definition) {
        const indicators = [];
        const tags = new Set(Array.isArray(definition.tags) ? definition.tags : []);

        if (providerCatalog.hasAdultFilter(definition)) {
            indicators.push(createIndicator('provider-adult-content-indicator',
                LangUtil.INDICATOR_ADULT_CONTENT, LangUtil.INDICATOR_ADULT_CONTENT));
        }

        if (tags.has('proxy')) {
            indicators.push(createIndicator('provider-proxy-indicator',
                LangUtil.INDICATOR_IP_PROTECTED, LangUtil.INDICATOR_IP_PROTECTED));
        }

        if (tags.has('partner')) {
            indicators.push(createIndicator('provider-badge partner-badge',
                LangUtil.OFFICIAL_PARTNER_TITLE, LangUtil.OFFICIAL_PARTNER_TITLE));
        }
        return indicators;
    }

    function createHeaderToggle(isEnabled) {
        return formHelpers.createElement('span', {
            className: `toggle-switch ${isEnabled ? 'on' : 'off'}`,
            role: 'switch',
            ariaChecked: isEnabled,
            tabIndex: 0,
        });
    }

    function createProviderHeader(definition, iconUrl, isEnabled, indicators = []) {
        const header = createDiv('provider-header');
        const toggleSwitch = createHeaderToggle(isEnabled);

        Object.assign(header, {
            tabIndex: 0
        });

        header.setAttribute('role', 'button');
        header.setAttribute('aria-expanded', 'false');

        header.append(
            createProviderLogo(definition.displayName, iconUrl),

            formHelpers.createElement('span', {
                className: 'provider-name',
                textContent: formHelpers.normalizeProviderName(definition.displayName) || 'Unnamed Provider',
            }),

            ...indicators,
            createDiv('provider-toggle-wrap', toggleSwitch),

            formHelpers.createElement('span', {
                className: 'expand-arrow',
                textContent: '▼'
            })
        );
        return {header, toggleSwitch};
    }

    function setToggleVisualState(toggleSwitch, isOn) {
        toggleSwitch.classList.toggle('on', isOn);
        toggleSwitch.classList.toggle('off', !isOn);
        toggleSwitch.setAttribute('aria-checked', String(isOn));
    }

    function toggleExpansion(item, header) {
        const expanded = item.classList.toggle('expanded');
        header.setAttribute('aria-expanded', String(expanded));
    }

    function wireProviderInteractions(item, header, toggleSwitch, providerId, {
        isThirdParty = false,
        getApiKey = () => '',
        onStateChanged,
        disabled = false,
    } = {}) {
        header.addEventListener('click', event => {
            if (!event.target.closest('.provider-toggle-wrap')) {
                toggleExpansion(item, header);
            }
        });

        header.addEventListener('keydown', event => {
            if ((event.key === 'Enter' || event.key === ' ') && event.target === header) {
                event.preventDefault();
                toggleExpansion(item, header);
            }
        });

        const handleToggleClick = () => {
            if (disabled) {
                return;
            }

            const wasEnabled = toggleSwitch.classList.contains('on');
            const nextState = !wasEnabled;

            if (nextState && isThirdParty) {
                const key = getApiKey();

                if (!key || !key.trim()) {
                    toast.show(LangUtil.TOAST_SAVE_API_KEY_FIRST, true);
                    setToggleVisualState(toggleSwitch, false);
                    return;
                }
            }

            setToggleVisualState(toggleSwitch, nextState);

            providerStateStore.setProviderEnabled(providerId, nextState).catch(error => {
                console.error(`ProviderCard failed to persist enabled state for provider '${providerId}'`, error);
                setToggleVisualState(toggleSwitch, wasEnabled);
                toast.show(LangUtil.TOAST_FAILED_TO_UPDATE_STATE, true);
            });

            onStateChanged?.();
        };

        if (disabled) {
            toggleSwitch.tabIndex = -1;
            toggleSwitch.setAttribute('aria-disabled', 'true');
            toggleSwitch.classList.add('disabled');
        }

        for (const [type, handler] of [
            ['click', event => {
                event.stopPropagation();
                handleToggleClick();
            }],

            ['keydown', event => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    event.stopPropagation();
                    handleToggleClick();
                }
            }]
        ]) {
            toggleSwitch.addEventListener(type, handler);
        }
    }

    function createCardShell(className, id, definition, iconUrl, isEnabled, indicators = []) {
        const item = formHelpers.createElement('div', {
            className: `provider-item ${className}`,
            dataset: {
                id
            }
        });

        const {header, toggleSwitch} = createProviderHeader(definition, iconUrl, isEnabled, indicators);
        const body = createDiv('provider-body');
        return {item, header, toggleSwitch, body};
    }

    function createBuiltInCard(definition, providerState, iconUrl, runtime = null) {
        const {item, header, toggleSwitch, body} = createCardShell(
            'built-in',
            definition.id,
            definition,
            iconUrl,
            Boolean(providerState?.enabled),
            buildIndicators(definition)
        );

        body.append(
            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_API_URL, formHelpers.createReadOnlyInput(providerCatalog.proxyEndpointUrl(definition))),
            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_METHOD, formHelpers.createReadOnlyInput('POST'))
        );

        wireProviderInteractions(item, header, toggleSwitch, definition.id, {
            disabled: Boolean(runtime?.effectiveState?.app?.lockSettings || runtime?.providerManagedIds?.has(definition.id))
        });

        item.append(header, body);
        return item;
    }

    function createThirdPartyCard(definition, providerState, iconUrl, runtime = null) {
        const isEnabled = Boolean(providerState?.enabled);
        const savedApiKey = String(providerState?.apiKey || '');

        const {
            item,
            header,
            toggleSwitch,
            body
        } = createCardShell('third-party', definition.id, definition, iconUrl, isEnabled);

        const fieldsLocked = Boolean(runtime?.effectiveState?.app?.lockSettings ||
            runtime?.effectiveState?.app?.disableThirdPartyIntegrations ||
            runtime?.providerManagedApiKeyIds?.has(definition.id));

        const passwordField = formHelpers.createPasswordField({
            value: formHelpers.sanitizeMultiline(savedApiKey, formHelpers.maxAPIKeyLength),
            dataset: {
                field: 'apiKey'
            },
        });

        const applyButton = formHelpers.createElement('button', {
            type: 'button',
            className: 'action-btn apply-btn third-party-apply-btn',
            textContent: LangUtil.APPLY_BUTTON,
            disabled: true,
        });

        const requestUrl = String(definition.request?.urlTemplate || '');
        const apiKeyUrl = String(definition?.apiKeyUrl || '').trim();
        const apiKeyLink = apiKeyUrl ? formHelpers.createElement('div', {
            className: 'api-key-link-text',
            textContent: 'Get API Key ↗',
            role: 'link',
            tabIndex: 0
        }) : null;

        if (apiKeyLink) {
            const openApiKeyUrl = () => {
                browserAPI?.tabsCreate?.({url: apiKeyUrl}).catch(error => {
                    console.error(`ProviderCard failed to open API key URL for provider '${definition?.id || 'unknown'}'`, error);
                    globalThis.open(apiKeyUrl, '_blank', 'noopener');
                });
            };

            apiKeyLink.addEventListener('click', event => {
                event.preventDefault();
                event.stopPropagation();
                openApiKeyUrl();
            });

            apiKeyLink.addEventListener('keydown', event => {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    event.stopPropagation();
                    openApiKeyUrl();
                }
            });
        }

        passwordField.input.disabled = fieldsLocked;

        const syncApplyState = () => setActionButtonState(
            applyButton,
            formHelpers.sanitizeMultiline(passwordField.input.value, formHelpers.maxAPIKeyLength) !== savedApiKey,
            'is-changed'
        );

        passwordField.input.addEventListener('input', syncApplyState);

        applyButton.addEventListener('click', () => {
            if (applyButton.disabled || fieldsLocked) {
                return;
            }

            const apiKey = formHelpers.normalizeApiKey(passwordField.input.value);
            const wasEnabled = Boolean(providerState?.enabled);

            (async () => {
                try {
                    await providerStateStore.setProviderApiKey(definition.id, apiKey);

                    if (apiKey.length === 0 && wasEnabled) {
                        await providerStateStore.setProviderEnabled(definition.id, false);
                    }

                    toast.show(LangUtil.TOAST_SAVED);
                    document.dispatchEvent(new CustomEvent('osprey:settings-changed'));
                } catch (error) {
                    console.error(`ProviderCard failed to save API key settings for provider '${definition.id}'`, error);
                    toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
                }
            })();
        });

        const apiKeyFieldGroup = formHelpers.createFieldGroup(
            LangUtil.FIELD_LABEL_API_KEY,
            passwordField.wrapper,
            null,
            apiKeyLink
        );

        body.append(
            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_API_URL, formHelpers.createReadOnlyInput(requestUrl)),
            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_METHOD, formHelpers.createReadOnlyInput(definition.request?.method || 'GET')),
            apiKeyFieldGroup,
            createDiv('provider-actions', applyButton)
        );

        wireProviderInteractions(item, header, toggleSwitch, definition.id, {
            isThirdParty: providerCatalog.requiresApiKey(definition),
            getApiKey: () => String(providerState?.apiKey || ''),
        });

        item.append(header, body);
        syncApplyState();
        return item;
    }

    function buildProviderCard(definition, providerState, state, runtime = null) {
        const iconUrl = providerCatalog.resolveIconUrl(definition, 2);

        switch (definition.kind) {
            case 'proxy_builtin':
                return createBuiltInCard(definition, providerState, iconUrl, runtime);

            case 'direct_static':
                return createThirdPartyCard(definition, providerState, iconUrl, runtime);

            default:
                return null;
        }
    }

    // Public API
    return Object.freeze({
        buildProviderCard
    });
})();
