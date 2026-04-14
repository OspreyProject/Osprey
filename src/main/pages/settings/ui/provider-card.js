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

    const comparisonOpMap = Object.freeze({
        equals: '===',
        not_equals: '!==',
        greater_than: '>',
        less_than: '<',
        greater_or_equal: '>=',
        less_or_equal: '<='
    });

    const createDiv = (className, ...children) => formHelpers.createElement('div', {className}, ...children);

    const createFieldLabel = textContent => formHelpers.createElement('label', {
        className: 'field-label',
        textContent
    });

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
        isCustom = false,
        getApiKey = () => '',
        validateCustom = () => ({ok: true}),
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

            if (nextState && isCustom) {
                const validation = validateCustom();

                if (!validation.ok) {
                    console.warn(`ProviderCard blocked enabling custom provider '${providerId}': ${validation.error}`);
                    toast.show(LangUtil.format('toastCannotEnableProvider', validation.error), true);
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

    function rulesToLogicBlocks(rules) {
        return Array.isArray(rules) ? rules.map(rule => {
            if (typeof rule?.condition === 'string' && rule.condition.trim()) {
                return {
                    condition: rule.condition.trim(),
                    resultType: String(rule.result || 'MALICIOUS')
                };
            }

            const op = comparisonOpMap[String(rule?.operator || '')] ||
                (String(rule?.operator || '') === 'contains' ? 'contains' : '');

            if (!op) {
                return null;
            }

            let val = rule?.value;

            if (typeof val === 'string') {
                val = JSON.stringify(val);
            } else if (typeof val !== 'number' && typeof val !== 'boolean') {
                return null;
            }

            return {
                condition: `response.${rule.path} ${op} ${String(val)}`,
                resultType: String(rule.result || 'MALICIOUS')
            };
        }).filter(Boolean) : [];
    }

    const persistCustomProviders = mutator => providerStateStore.getState().then(state => {
        const existing = Object.values(state.customProviders || {});
        return providerStateStore.setCustomProviders(mutator(existing.slice(), state) || existing);
    });

    function serializeProviderSnapshot(value) {
        return JSON.stringify({
            name: value.name,
            apiUrl: value.apiUrl,
            method: value.method,
            apiKey: value.apiKey,
            requestHeaders: value.requestHeaders,
            requestBody: value.requestBody,
            logicBlocks: value.logicBlocks
        });
    }

    function snapshotCustomProvider(provider) {
        const record = provider && typeof provider === 'object' ? provider : {};

        const hasStoredDefinitionShape = typeof record.displayName === 'string' ||
            typeof record.request === 'object' || Array.isArray(record.responseRules);

        if (hasStoredDefinitionShape) {
            const request = record.request || {};

            return serializeProviderSnapshot({
                name: formHelpers.normalizeProviderName(record.displayName ?? record.name ?? ''),
                apiUrl: formHelpers.sanitizeSingleLine(request.urlTemplate ?? record.apiUrl ?? '', 2048),
                method: String(request.method ?? record.method ?? 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
                apiKey: formHelpers.normalizeApiKey(record.apiKey ?? ''),
                requestHeaders: formHelpers.sanitizeMultiline(
                    Array.isArray(request.headers) ?
                        request.headers.map(header => `${header?.name || ''}: ${header?.value || ''}`).join('\n') :
                        record.requestHeaders ?? '',
                    formHelpers.maxHeadersLength
                ),
                requestBody: formHelpers.sanitizeMultiline(request.bodyTemplate ?? record.requestBody ?? '', formHelpers.maxBodyLength),
                logicBlocks: rulesToLogicBlocks(record.responseRules)
            });
        }

        const normalized = formHelpers.normalizeCustomProviderInput(record ?? {});
        return normalized.ok ? serializeProviderSnapshot(normalized.value) : null;
    }

    function collectCustomProviderDraftSnapshot(body, providerId) {
        const readField = selector => body.querySelector(selector)?.value ?? '';

        return serializeProviderSnapshot({
            id: providerId,
            name: formHelpers.normalizeProviderName(readField('[data-field="name"]')),
            apiUrl: formHelpers.sanitizeSingleLine(readField('[data-field="apiUrl"]'), 2048),
            method: String(readField('[data-field="method"]') || 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
            apiKey: formHelpers.normalizeApiKey(readField('[data-field="apiKey"]')),
            requestHeaders: formHelpers.sanitizeMultiline(readField('[data-field="requestHeaders"]'), formHelpers.maxHeadersLength),
            requestBody: formHelpers.sanitizeMultiline(readField('[data-field="requestBody"]'), formHelpers.maxBodyLength),
            logicBlocks: formHelpers.readLogicBlocks(body).map(rule => ({
                condition: formHelpers.sanitizeSingleLine(rule?.condition ?? '', 200),
                resultType: String(rule?.resultType || 'MALICIOUS')
            }))
        });
    }

    function collectCustomProviderFromBody(body, providerId) {
        const readField = selector => body.querySelector(selector)?.value ?? '';

        return formHelpers.normalizeCustomProviderInput({
            id: providerId,
            name: readField('[data-field="name"]'),
            apiUrl: readField('[data-field="apiUrl"]'),
            method: readField('[data-field="method"]'),
            apiKey: readField('[data-field="apiKey"]'),
            requestHeaders: readField('[data-field="requestHeaders"]'),
            requestBody: readField('[data-field="requestBody"]'),
            logicBlocks: formHelpers.readLogicBlocks(body),
        }, {
            providerId
        });
    }

    function createHalfField(labelText, control) {
        return createDiv('field-group field-half', createFieldLabel(labelText), control);
    }

    function createCustomCard(definition, providerState, existingRawDefinition, runtime = null) {
        const providerId = definition.id;
        const savedApiKey = String(providerState?.apiKey || '');

        const {
            item,
            header,
            toggleSwitch,
            body
        } = createCardShell('custom', providerId, definition, '', Boolean(providerState?.enabled));

        const passwordField = formHelpers.createPasswordField({
            value: formHelpers.sanitizeMultiline(savedApiKey, formHelpers.maxAPIKeyLength),
            dataset: {
                field: 'apiKey'
            },
        });

        const nameInput = formHelpers.createEditableInput({
            value: formHelpers.normalizeProviderName(definition.displayName ?? ''),
            dataset: {
                field: 'name'
            },
        });

        const apiUrlInput = formHelpers.createEditableInput({
            value: formHelpers.sanitizeSingleLine(definition.request?.urlTemplate ?? '', 2048),
            placeholder: 'https://api.example.com/check',
            dataset: {
                field: 'apiUrl'
            },
        });

        const methodSelect = formHelpers.createMethodSelect(
            String(definition.request?.method ?? 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
            {
                field: 'method'
            },
        );

        const requestHeaders = formHelpers.createEditableTextArea({
            value: formHelpers.sanitizeMultiline(
                Array.isArray(definition.request?.headers) ? definition.request.headers.map(hdr => `${hdr.name}: ${hdr.value}`).join('\n') : '',
                formHelpers.maxHeadersLength,
            ),
            placeholder: 'X-API-Key: {api_key}',
            dataset: {
                field: 'requestHeaders'
            },
        });

        const requestBody = formHelpers.createEditableTextArea({
            value: formHelpers.sanitizeMultiline(definition.request?.bodyTemplate ?? '', formHelpers.maxBodyLength),
            placeholder: '{"url": "{url}"}',
            dataset: {
                field: 'requestBody'
            },
        });

        const fieldsLocked = Boolean(runtime?.effectiveState?.app?.lockSettings || runtime?.effectiveState?.app?.disableCustomProviders);

        const applyButton = formHelpers.createElement('button', {
            type: 'button',
            className: 'action-btn apply-btn',
            textContent: LangUtil.APPLY_BUTTON,
            disabled: true
        });

        const deleteButton = formHelpers.createElement('button', {
            type: 'button',
            className: 'action-btn delete-btn',
            textContent: LangUtil.DELETE_BUTTON,
            disabled: fieldsLocked
        });

        let savedSnapshot = snapshotCustomProvider(existingRawDefinition);
        let savedDraftSnapshot = savedSnapshot;

        const syncApplyState = () => {
            const liveDraftSnapshot = collectCustomProviderDraftSnapshot(body, providerId);
            const changed = Boolean(savedDraftSnapshot && liveDraftSnapshot !== savedDraftSnapshot);
            setActionButtonState(applyButton, changed, 'is-changed');
        };

        const logicEditor = formHelpers.createLogicBlockEditor(rulesToLogicBlocks(definition.responseRules), syncApplyState);
        const fields = [nameInput, apiUrlInput, methodSelect, passwordField.input, requestHeaders, requestBody];

        body.append(
            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_NAME, nameInput),
            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_API_URL, apiUrlInput, formHelpers.createRequiredTag('*')),

            createDiv('field-row',
                createHalfField(LangUtil.FIELD_LABEL_METHOD, methodSelect),
                createHalfField(LangUtil.FIELD_LABEL_API_KEY, passwordField.wrapper)
            ),

            formHelpers.createFieldGroup(
                LangUtil.FIELD_LABEL_REQUEST_HEADERS,
                requestHeaders,
                null,
                formHelpers.createFieldHelp(LangUtil.TAG_REQUEST_HEADERS_HINT)
            ),

            formHelpers.createFieldGroup(
                LangUtil.FIELD_LABEL_REQUEST_BODY,
                requestBody,
                null,
                formHelpers.createFieldHelp(LangUtil.TAG_REQUEST_BODY_HINT)
            ),

            logicEditor,
            createDiv('provider-actions', applyButton, deleteButton)
        );

        for (const field of fields) {
            field.disabled = fieldsLocked;

            for (const type of ['input', 'change']) {
                field.addEventListener(type, syncApplyState);
            }
        }

        applyButton.addEventListener('click', () => {
            if (applyButton.disabled || fieldsLocked) {
                return;
            }

            const normalized = collectCustomProviderFromBody(body, providerId);

            if (!normalized.ok) {
                console.warn(`ProviderCard rejected custom provider save for '${providerId}': ${normalized.error}`);
                toast.show(normalized.error, true);
                return;
            }

            persistCustomProviders(existing => existing.map(p => p.id === providerId ? normalized.value : p)).then(() => {
                savedSnapshot = serializeProviderSnapshot(normalized.value);
                savedDraftSnapshot = collectCustomProviderDraftSnapshot(body, providerId);
                syncApplyState();
                toast.show(LangUtil.TOAST_SAVED);
                document.dispatchEvent(new CustomEvent('osprey:settings-changed'));
            }).catch(error => {
                console.error(`ProviderCard failed to save custom provider '${providerId}'`, error);
                toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
            });
        });

        deleteButton.addEventListener('click', () => {
            if (fieldsLocked) {
                return;
            }

            persistCustomProviders(existing => existing.filter(p => p.id !== providerId)).then(() => {
                toast.show(LangUtil.TOAST_PROVIDER_DELETED);
                document.dispatchEvent(new CustomEvent('osprey:settings-changed'));
            }).catch(error => {
                console.error(`ProviderCard failed to delete custom provider '${providerId}'`, error);
                toast.show(LangUtil.TOAST_FAILED_TO_DELETE, true);
            });
        });

        wireProviderInteractions(item, header, toggleSwitch, providerId, {
            isCustom: true,
            validateCustom: () => collectCustomProviderFromBody(body, providerId),
            disabled: fieldsLocked,
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

            case 'direct_custom':
                const rawDef = state?.customProviders?.[definition.id] || definition;
                return createCustomCard(definition, providerState, rawDef, runtime);

            default:
                return createCustomCard(definition, providerState, definition, runtime);
        }
    }

    // Public API
    return Object.freeze({
        buildProviderCard
    });
})();
