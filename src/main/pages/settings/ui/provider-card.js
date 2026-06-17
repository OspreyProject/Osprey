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

globalThis.OspreyProviderCard = (() => {
    const formHelpers = globalThis.OspreyFormHelpers;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const browserAPI = globalThis.OspreyBrowserAPI;
    const toast = globalThis.OspreyToast;

    const clickString = 'click';
    const keydownString = 'keydown';
    const enterString = 'Enter';
    const spaceString = ' ';
    const onString = 'on';
    const offString = 'off';

    const maxLogoCacheSize = 100;
    const logoUrlCache = new Map();
    const headerContextMap = new WeakMap();

    const passiveListenerOptions = {passive: true};
    const captureListenerOptions = {capture: false};

    const sanitizeExternalUrl = rawUrl => {
        const raw = String(rawUrl ?? '').trim();

        if (!raw) {
            return '';
        }

        try {
            const parsed = new URL(raw, document.baseURI);

            if (parsed.protocol === 'https:' || parsed.protocol === 'http:') {
                return parsed.toString();
            }
        } catch {
            // ignored
        }
        return '';
    };

    const openExternalUrl = (url, providerId) => {
        if (browserAPI?.tabsCreate) {
            browserAPI.tabsCreate({url}).catch(error => {
                console.error(`ProviderCard failed to open external URL via browserAPI for provider '${providerId || 'unknown'}'`, error);
                globalThis.open(url, '_blank', 'noopener');
            });
        } else {
            globalThis.open(url, '_blank', 'noopener');
        }
    };

    const createExternalLinkText = (rawUrl, label, className, providerId) => {
        const safeUrl = sanitizeExternalUrl(rawUrl);

        if (!safeUrl) {
            return null;
        }

        const link = formHelpers.createElement('div', {
            className,
            textContent: label,
            role: 'link',
            tabIndex: 0,
        });

        const open = () => openExternalUrl(safeUrl, providerId);

        link.addEventListener(clickString, event => {
            event.preventDefault();
            event.stopPropagation();
            open();
        }, captureListenerOptions);

        link.addEventListener(keydownString, event => {
            if (event.key === enterString || event.key === spaceString) {
                event.preventDefault();
                event.stopPropagation();
                open();
            }
        }, captureListenerOptions);
        return link;
    };

    function onHeaderClick(event) {
        if (!event.target.closest('.provider-toggle-wrap')) {
            const currentItem = headerContextMap.get(event.currentTarget);

            if (currentItem) {
                const expanded = currentItem.classList.toggle('expanded');
                event.currentTarget.setAttribute('aria-expanded', String(expanded));
            }
        }
    }

    function onHeaderKeyDown(event) {
        if ((event.key === enterString || event.key === spaceString) && event.target === event.currentTarget) {
            event.preventDefault();
            const currentItem = headerContextMap.get(event.currentTarget);

            if (currentItem) {
                const expanded = currentItem.classList.toggle('expanded');
                event.currentTarget.setAttribute('aria-expanded', String(expanded));
            }
        }
    }

    const createDiv = (className, ...children) => formHelpers.createElement('div', {className}, ...children);

    const createFallbackLogo = () => formHelpers.createElement('span', {
        className: 'provider-logo-fallback',
        attributes: {
            'aria-hidden': 'true',
        },
    });

    function setActionButtonState(button, isActive, activeClassName) {
        button.disabled = !isActive;
        button.classList.toggle(activeClassName, isActive);
    }

    function cacheLogoUrl(source, urlString) {
        logoUrlCache.set(source, urlString);

        if (logoUrlCache.size > maxLogoCacheSize) {
            logoUrlCache.delete(logoUrlCache.keys().next().value);
        }
    }

    function createProviderLogo(name, logoUrl) {
        const safeName = formHelpers.normalizeProviderName(name) || LangUtil.PROVIDER_NAME_FALLBACK;
        const source = String(logoUrl ?? '').trim();

        if (!source) {
            return createFallbackLogo();
        }

        if (logoUrlCache.has(source)) {
            const cachedResult = logoUrlCache.get(source);

            logoUrlCache.delete(source);
            logoUrlCache.set(source, cachedResult);

            if (cachedResult === null) {
                return createFallbackLogo();
            }

            return formHelpers.createElement('img', {
                className: 'provider-logo',
                src: cachedResult,
                alt: LangUtil.format('providerLogoAlt', safeName),
                attributes: {
                    loading: 'lazy',
                    decoding: 'async',
                    referrerpolicy: 'no-referrer',
                },
            });
        }

        try {
            const parsed = new URL(source, document.baseURI);
            const protocol = parsed.protocol;
            const ok = protocol === 'https:' || protocol === 'chrome-extension:' || protocol === 'moz-extension:' || protocol === 'data:';

            if (!ok) {
                throw new Error('Unsupported logo protocol');
            }

            const urlString = parsed.toString();
            cacheLogoUrl(source, urlString);

            return formHelpers.createElement('img', {
                className: 'provider-logo',
                src: urlString,
                alt: LangUtil.format('providerLogoAlt', safeName),
                attributes: {
                    loading: 'lazy',
                    decoding: 'async',
                    referrerpolicy: 'no-referrer',
                },
            });
        } catch {
            cacheLogoUrl(source, null);
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
                'data-tooltip': tooltip,
            },
        });
    }

    function buildIndicators(definition) {
        const indicators = [];
        const tags = definition.tags;

        if (Array.isArray(tags)) {
            if (tags.includes('proxy')) {
                indicators.push(createIndicator('provider-proxy-indicator',
                    LangUtil.INDICATOR_IP_PROTECTED, LangUtil.INDICATOR_IP_PROTECTED));
            }

            if (tags.includes('partner')) {
                indicators.push(createIndicator('provider-badge partner-badge',
                    LangUtil.OFFICIAL_PARTNER_TITLE, LangUtil.OFFICIAL_PARTNER_TITLE));
            }
        }
        return indicators;
    }

    function createHeaderToggle(isEnabled) {
        return formHelpers.createElement('span', {
            className: isEnabled ? 'toggle-switch on' : 'toggle-switch off',
            role: 'switch',
            ariaChecked: isEnabled,
            tabIndex: 0,
        });
    }

    function createProviderHeader(definition, iconUrl, isEnabled, indicators = []) {
        const header = createDiv('provider-header');
        const toggleSwitch = createHeaderToggle(isEnabled);

        header.tabIndex = 0;
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
                textContent: '▼',
            }),
        );
        return {header, toggleSwitch};
    }

    function setToggleVisualState(toggleSwitch, isOn) {
        toggleSwitch.classList.toggle(onString, isOn);
        toggleSwitch.classList.toggle(offString, !isOn);
        toggleSwitch.setAttribute('aria-checked', isOn ? 'true' : 'false');
    }

    function wireProviderInteractions(item, header, toggleSwitch, providerId, options = {}) {
        const isThirdParty = options.isThirdParty === true;
        const getApiKey = options.getApiKey || null;
        const onStateChanged = options.onStateChanged || null;
        const disabled = options.disabled === true;

        headerContextMap.set(header, item);
        header.addEventListener(clickString, onHeaderClick, captureListenerOptions);
        header.addEventListener(keydownString, onHeaderKeyDown, captureListenerOptions);

        const handleToggleClick = () => {
            if (disabled) {
                return;
            }

            const wasEnabled = toggleSwitch.classList.contains(onString);
            const nextState = !wasEnabled;

            if (nextState && isThirdParty && getApiKey) {
                const key = getApiKey();

                if (!key?.trim()) {
                    toast.show(LangUtil.TOAST_SAVE_API_KEY_FIRST, true);
                    setToggleVisualState(toggleSwitch, false);
                    return;
                }
            }

            setToggleVisualState(toggleSwitch, nextState);

            providerStateStore.setProviderEnabled(providerId, nextState)
                .then(() => {
                    if (onStateChanged) {
                        onStateChanged();
                    }
                })
                .catch(error => {
                    console.error(`ProviderCard failed to persist enabled state for provider '${providerId}'`, error);
                    setToggleVisualState(toggleSwitch, wasEnabled);
                    toast.show(LangUtil.TOAST_FAILED_TO_UPDATE_STATE, true);
                });
        };

        if (disabled) {
            toggleSwitch.tabIndex = -1;
            toggleSwitch.setAttribute('aria-disabled', 'true');
            toggleSwitch.classList.add('disabled');
        }

        toggleSwitch.addEventListener(clickString, event => {
            event.stopPropagation();
            handleToggleClick();
        }, captureListenerOptions);

        toggleSwitch.addEventListener(keydownString, event => {
            if (event.key === enterString || event.key === spaceString) {
                event.preventDefault();
                event.stopPropagation();
                handleToggleClick();
            }
        }, captureListenerOptions);
    }

    function createBypassThresholdControl(definition, providerState, disabled) {
        const defaultValue = Boolean(definition.bypassBlockingThreshold);

        const currentValue = typeof providerState?.bypassBlockingThreshold === 'boolean' ?
            providerState.bypassBlockingThreshold :
            defaultValue;

        const checkboxId = `bypass-threshold-${definition.id}`;

        const checkbox = formHelpers.createElement('input', {
            type: 'checkbox',
            id: checkboxId,
            className: 'provider-bypass-checkbox',
            disabled,
        });

        checkbox.checked = currentValue;

        const labelText = formHelpers.createElement('span', {
            className: 'provider-bypass-label-text',
            textContent: LangUtil.BYPASS_BLOCKING_THRESHOLD,
        });

        const row = formHelpers.createElement('label', {
            className: 'provider-bypass-row',
            attributes: {
                for: checkboxId,
                title: LangUtil.BYPASS_BLOCKING_THRESHOLD_TOOLTIP,
            },
        }, checkbox, labelText);

        if (disabled) {
            row.classList.add('disabled');
            return row;
        }

        checkbox.addEventListener('change', () => {
            const nextValue = checkbox.checked;

            providerStateStore.setBypassBlockingThreshold(definition.id, nextValue)
                .catch(error => {
                    console.error(`ProviderCard failed to persist bypass threshold for provider '${definition.id}'`, error);
                    checkbox.checked = !nextValue;
                    toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
                });
        }, passiveListenerOptions);
        return row;
    }

    function createCardShell(className, id, definition, iconUrl, isEnabled, indicators = []) {
        const item = formHelpers.createElement('div', {
            className: `provider-item ${className}`,
            dataset: {id},
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
            buildIndicators(definition),
        );

        const websiteLink = createExternalLinkText(definition.website, LangUtil.WEBSITE_LINK + ' ↗', 'provider-website-link', definition.id);

        const isDisabled = Boolean(
            runtime?.effectiveState?.app?.lockSettings ||
            runtime?.providerManagedIds?.has(definition.id),
        );

        const bypassControl = createBypassThresholdControl(definition, providerState, isDisabled);

        body.append(...[
            websiteLink,
            bypassControl,
        ].filter(node => node !== null));

        wireProviderInteractions(item, header, toggleSwitch, definition.id, {
            disabled: isDisabled,
        });

        item.append(header, body);
        return item;
    }

    function createThirdPartyCard(definition, providerState, iconUrl, runtime = null) {
        const isEnabled = Boolean(providerState?.enabled);
        const savedApiKey = String(providerState?.apiKey || '');

        const {item, header, toggleSwitch, body} = createCardShell(
            'third-party',
            definition.id,
            definition,
            iconUrl,
            isEnabled,
        );

        const fieldsLocked = Boolean(
            runtime?.effectiveState?.app?.lockSettings ||
            runtime?.effectiveState?.app?.disableThirdPartyIntegrations ||
            runtime?.providerManagedApiKeyIds?.has(definition.id),
        );

        const toggleLocked = Boolean(
            runtime?.effectiveState?.app?.lockSettings ||
            runtime?.effectiveState?.app?.disableThirdPartyIntegrations ||
            runtime?.providerManagedIds?.has(definition.id),
        );

        const passwordField = formHelpers.createPasswordField({
            value: formHelpers.sanitizeMultiline(savedApiKey, formHelpers.maxAPIKeyLength),
            dataset: {field: 'apiKey'},
        });

        const applyButton = formHelpers.createElement('button', {
            type: 'button',
            className: 'action-btn apply-btn third-party-apply-btn',
            textContent: LangUtil.APPLY_BUTTON,
            disabled: true,
        });

        const apiKeyLink = createExternalLinkText(definition.apiKeyUrl, LangUtil.GET_API_KEY + ' ↗', 'api-key-link-text', definition.id);

        passwordField.input.disabled = fieldsLocked;

        const syncApplyState = () => {
            const currentInputValue = formHelpers.sanitizeMultiline(passwordField.input.value, formHelpers.maxAPIKeyLength);
            setActionButtonState(applyButton, currentInputValue !== savedApiKey, 'is-changed');
        };

        passwordField.input.addEventListener('input', syncApplyState, passiveListenerOptions);

        applyButton.addEventListener(clickString, () => {
            if (applyButton.disabled || fieldsLocked) {
                return;
            }

            const apiKey = formHelpers.normalizeApiKey(passwordField.input.value);

            (async () => {
                try {
                    await providerStateStore.setProviderApiKey(definition.id, apiKey);

                    if (apiKey.length === 0) {
                        const sharedMembers = providerCatalog.getSharedGroupMembersById(definition.id);
                        const idsToDisable = sharedMembers.length > 0 ? sharedMembers : [definition.id];

                        for (const memberId of idsToDisable) {
                            await providerStateStore.setProviderEnabled(memberId, false);
                        }

                        setToggleVisualState(toggleSwitch, false);
                    }

                    toast.show(LangUtil.TOAST_SAVED);
                    document.dispatchEvent(new CustomEvent('osprey:settings-changed'));
                } catch (error) {
                    console.error(`ProviderCard failed to save API key settings for provider '${definition.id}'`, error);
                    toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
                }
            })();
        }, captureListenerOptions);

        const apiKeyFieldGroup = formHelpers.createFieldGroup(
            LangUtil.FIELD_LABEL_API_KEY,
            passwordField.wrapper,
            null,
            apiKeyLink,
        );

        const websiteLink = createExternalLinkText(definition.website, LangUtil.WEBSITE_LINK + ' ↗', 'provider-website-link', definition.id);
        const bypassControl = createBypassThresholdControl(definition, providerState, toggleLocked);

        body.append(...[
            websiteLink,
            bypassControl,
            apiKeyFieldGroup,
            createDiv('provider-actions', applyButton),
        ].filter(node => node !== null));

        const getSavedKeyField = () => String(providerState?.apiKey || '');

        wireProviderInteractions(item, header, toggleSwitch, definition.id, {
            isThirdParty: providerCatalog.requiresApiKey(definition),
            getApiKey: getSavedKeyField,
            disabled: toggleLocked,
        });

        item.append(header, body);
        syncApplyState();
        return item;
    }

    function buildProviderCard(definition, providerState, runtime = null) {
        if (!definition) {
            return null;
        }

        const iconUrl = providerCatalog.resolveIconUrl(definition, 2);
        const kind = definition.kind;

        if (kind === 'proxy_builtin') {
            return createBuiltInCard(definition, providerState, iconUrl, runtime);
        } else if (kind === 'direct_static') {
            return createThirdPartyCard(definition, providerState, iconUrl, runtime);
        }
        return null;
    }

    return Object.freeze({
        buildProviderCard,
    });
})();
