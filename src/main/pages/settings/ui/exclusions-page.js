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

globalThis.OspreyExclusionsPage = (() => {
    const browserAPI = globalThis.OspreyBrowserAPI;
    const formHelpers = globalThis.OspreyFormHelpers;
    const messageBus = globalThis.OspreyMessageBus;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const toast = globalThis.OspreyToast;
    const urlService = globalThis.OspreyUrlService;

    const messages = messageBus.Messages;

    let cachedContainer = null;
    let currentRuntime = null;
    let isBusy = false;
    let pendingFocusAdd = false;

    const send = (messageType, extra) => browserAPI.runtimeSendMessage({messageType, ...extra});

    const resolveContainer = () => {
        if (!cachedContainer?.isConnected) {
            cachedContainer = document.getElementById('exclusionsList');
        }
        return cachedContainer;
    };

    const isReadOnly = () => Boolean(currentRuntime?.effectiveState?.app?.disableClearAllowedWebsites);

    const patternToHost = pattern =>
        (typeof pattern === 'string' && pattern.startsWith('*.') ? pattern.slice(2) : String(pattern || ''));

    const describeLookupKey = lookupKey => {
        const key = String(lookupKey || '');

        if (key.includes('://')) {
            const parsed = urlService.parseHttpUrl(key);

            if (parsed) {
                let detail = parsed.pathname || '';

                if (detail === '/') {
                    detail = '';
                }

                return {
                    host: urlService.canonicalizeHostname(parsed.hostname),
                    detail
                };
            }
        }

        return {
            host: urlService.canonicalizeHostname(key),
            detail: ''
        };
    };

    const providerDisplayName = (definition, providerId) =>
        formHelpers.normalizeProviderName(definition?.displayName) || providerId || LangUtil.PROVIDER_NAME_FALLBACK;

    const runAction = async factory => {
        if (isBusy) {
            return;
        }

        isBusy = true;

        try {
            await factory();
        } catch (error) {
            console.error('ExclusionsPage action failed', error);
            toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
        } finally {
            isBusy = false;
        }
    };

    const addSite = rawValue => {
        const value = String(rawValue || '').trim();

        if (!value) {
            resolveContainer()?.querySelector('.excl-add-input')?.focus();
            return;
        }

        return runAction(async () => {
            const response = await send(messages.ADD_GLOBAL_EXCLUSION, {host: value});

            if (!response?.ok) {
                toast.show(LangUtil.TOAST_EXCLUSION_INVALID, true);
                return;
            }

            if (response.added) {
                toast.show(LangUtil.format('toastExclusionAdded', [response.host]));
            } else {
                toast.show(LangUtil.format('toastExclusionExists', [response.host]));
            }

            pendingFocusAdd = true;
            await render();
        });
    };

    const removeGlobal = pattern => runAction(async () => {
        const response = await send(messages.REMOVE_GLOBAL_EXCLUSION, {pattern});

        if (response?.ok) {
            toast.show(LangUtil.TOAST_EXCLUSION_REMOVED);
        }

        await render();
    });

    const removeProviderEntries = entries => runAction(async () => {
        await Promise.all(entries.map(entry => send(messages.REMOVE_PROVIDER_EXCLUSION, {
            providerId: entry.providerId,
            lookupKey: entry.lookupKey
        })));

        toast.show(LangUtil.TOAST_EXCLUSION_REMOVED);
        await render();
    });

    const clearAll = () => runAction(async () => {
        const response = await send(messages.CLEAR_ALLOWED_WEBSITES, {});

        if (response?.ok) {
            toast.show(LangUtil.CLEAR_ALLOWED_WEBSITES_MESSAGE);
        } else {
            toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
        }

        await render();
    });

    const createDot = variant => formHelpers.createElement('span', {
        className: `excl-dot excl-dot-${variant}`
    });

    const createRemoveButton = (accessibleName, onClick) => {
        const button = formHelpers.createElement('button', {
            type: 'button',
            className: 'excl-remove',
            textContent: '\u00D7',
            ariaLabel: accessibleName,
            title: accessibleName,
        });

        button.addEventListener('click', onClick);
        return button;
    };

    const createBodyButton = (label, onClick) => {
        const button = formHelpers.createElement('button', {
            type: 'button',
            className: 'reset-btn reset-providers-btn',
            textContent: label,
        });

        button.addEventListener('click', onClick);
        return button;
    };

    const createExpandableCard = ({leading, title, trailing, body}) => {
        const item = formHelpers.createElement('div', {
            className: 'provider-item excl-item'
        });

        const header = formHelpers.createElement('div', {
            className: 'provider-header',
            role: 'button',
            tabIndex: 0,
            ariaExpanded: false,
        });

        const nameElement = formHelpers.createElement('span', {
            className: 'provider-name excl-item-host',
            textContent: title,
        });

        const arrow = formHelpers.createElement('span', {
            className: 'expand-arrow'
        }, formHelpers.createElement('span', {
            className: 'expand-arrow-glyph',
            textContent: '\u25BC',
            attributes: {'aria-hidden': 'true'},
        }));

        header.append(leading, nameElement);

        if (trailing) {
            header.appendChild(trailing);
        }

        header.appendChild(arrow);

        const bodyElement = formHelpers.createElement('div', {className: 'excl-item-body'}, ...body);

        const toggle = () => {
            const expanded = item.classList.toggle('expanded');
            header.setAttribute('aria-expanded', String(expanded));
        };

        header.addEventListener('click', toggle);

        header.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                toggle();
            }
        });

        item.append(header, bodyElement);
        return item;
    };

    const createSectionLabel = labelText => formHelpers.createElement('p', {
        className: 'section-label',
        textContent: labelText
    });

    const createEmptyState = text => formHelpers.createElement('p', {
        className: 'excl-empty',
        textContent: text
    });

    const buildAddRow = () => {
        const input = formHelpers.createElement('input', {
            className: 'field-input field-enabled excl-add-input',
            type: 'text',
            placeholder: 'example.com',
            ariaLabel: LangUtil.ADD_SITE_ARIA_LABEL,
            autocomplete: 'off',
            spellcheck: false,
        });

        input.addEventListener('keydown', event => {
            if (event.key === 'Enter') {
                event.preventDefault();

                addSite(input.value).then(() => {
                    // ignored
                });
            }
        });

        const button = formHelpers.createElement('button', {
            type: 'button',
            className: 'excl-add-btn',
            textContent: LangUtil.ADD_SITE_BUTTON,
        });

        button.addEventListener('click', () => addSite(input.value));

        return formHelpers.createElement('div', {
            className: 'excl-add'
        }, input, button);
    };

    const buildTrustedRow = (pattern, readOnly) => {
        const host = patternToHost(pattern);

        const row = formHelpers.createElement('div', {
                className: 'excl-row'
            },

            createDot('trusted'),

            formHelpers.createElement('span', {
                className: 'excl-row-host',
                textContent: host
            }),
        );

        if (!readOnly) {
            const removeButton = formHelpers.createElement('button', {
                type: 'button',
                className: 'reset-btn reset-providers-btn excl-row-remove',
                textContent: LangUtil.REMOVE_EXCLUSION_LABEL,
            });

            removeButton.addEventListener('click', () => removeGlobal(pattern));
            row.appendChild(removeButton);
        }
        return row;
    };

    const buildTrustedSection = (patterns, readOnly) => {
        const section = formHelpers.createElement('section', {
            className: 'excl-section'
        });

        section.appendChild(createSectionLabel(LangUtil.TRUSTED_SITES_LABEL));

        if (!readOnly) {
            section.appendChild(buildAddRow());
        }

        if (patterns.length === 0) {
            section.appendChild(createEmptyState(LangUtil.NO_TRUSTED_SITES));
            return section;
        }

        const list = formHelpers.createElement('div', {
            className: 'excl-list'
        });

        const sorted = patterns.slice().sort((a, b) => patternToHost(a).localeCompare(patternToHost(b)));

        for (let i = 0, len = sorted.length; i < len; i++) {
            list.appendChild(buildTrustedRow(sorted[i], readOnly));
        }

        section.appendChild(list);
        return section;
    };

    const buildProviderLogo = definition => {
        const iconUrl = providerCatalog.resolveIconUrl(definition, 2);

        if (!iconUrl) {
            return createDot('provider');
        }

        return formHelpers.createElement('img', {
            className: 'provider-logo',
            src: iconUrl,
            alt: '',
        });
    };

    const buildBypassEntry = (entry, readOnly) => {
        const row = formHelpers.createElement('div', {
            className: 'excl-entry'
        });

        row.appendChild(buildProviderLogo(entry.definition));

        row.appendChild(formHelpers.createElement('span', {
            className: 'excl-entry-name',
            textContent: entry.name,
        }));

        if (entry.detail) {
            row.appendChild(formHelpers.createElement('span', {
                className: 'excl-entry-detail',
                textContent: entry.detail,
                title: entry.detail,
            }));
        }

        row.appendChild(formHelpers.createElement('span', {
            className: 'excl-temp-badge',
            textContent: LangUtil.TEMPORARY_BADGE,
            title: LangUtil.TEMPORARY_BADGE_TOOLTIP,
        }));

        if (!readOnly) {
            row.appendChild(createRemoveButton(
                `${LangUtil.REMOVE_EXCLUSION_LABEL}: ${entry.name} - ${entry.host}`,
                () => removeProviderEntries([entry]),
            ));
        }
        return row;
    };

    const buildBypassCard = (host, entries, readOnly) => {
        const sorted = entries.slice().sort((a, b) => a.name.localeCompare(b.name));
        const body = [];

        for (let i = 0, len = sorted.length; i < len; i++) {
            body.push(buildBypassEntry(sorted[i], readOnly));
        }

        if (!readOnly) {
            body.push(createBodyButton(LangUtil.REMOVE_ALL_FOR_SITE, () => removeProviderEntries(entries)));
        }

        const count = formHelpers.createElement('span', {
            className: 'excl-count',
            textContent: String(entries.length),
        });

        return createExpandableCard({
            leading: createDot('provider'),
            title: host,
            trailing: count,
            body,
        });
    };

    const groupBypasses = providers => {
        const groups = new Map();
        const providerIds = Object.keys(providers || {});

        for (let i = 0, len = providerIds.length; i < len; i++) {
            const providerId = providerIds[i];
            const definition = providerCatalog.getDefinition(providerId);
            const name = providerDisplayName(definition, providerId);
            const entries = providers[providerId];

            for (let j = 0, entryLen = entries.length; j < entryLen; j++) {
                const {lookupKey} = entries[j];
                const {host, detail} = describeLookupKey(lookupKey);

                let bucket = groups.get(host);

                if (!bucket) {
                    bucket = [];
                    groups.set(host, bucket);
                }

                bucket.push({providerId, definition, name, host, detail, lookupKey});
            }
        }
        return groups;
    };

    const buildBypassSection = (providers, readOnly) => {
        const section = formHelpers.createElement('section', {
            className: 'excl-section'
        });

        section.appendChild(createSectionLabel(LangUtil.BYPASSES_LABEL));

        const groups = groupBypasses(providers);

        if (groups.size === 0) {
            section.appendChild(createEmptyState(LangUtil.NO_BYPASSES));
            return section;
        }

        const list = formHelpers.createElement('div', {
            className: 'excl-list'
        });

        const hosts = Array.from(groups.keys()).sort((a, b) => a.localeCompare(b));

        for (let i = 0, len = hosts.length; i < len; i++) {
            const host = hosts[i];
            list.appendChild(buildBypassCard(host, groups.get(host), readOnly));
        }

        section.appendChild(list);
        return section;
    };

    const buildClearFooter = () => {
        const footer = formHelpers.createElement('div', {
            className: 'excl-footer'
        });

        const clearButton = formHelpers.createElement('button', {
            type: 'button',
            className: 'reset-btn reset-all-btn',
            textContent: LangUtil.CLEAR_ALLOWED_WEBSITES,
        });

        clearButton.addEventListener('click', () => clearAll());
        footer.appendChild(clearButton);
        return footer;
    };

    const buildContent = (data, readOnly) => {
        const wrapper = formHelpers.createElement('div', {
            className: 'exclusions'
        });

        if (readOnly) {
            wrapper.appendChild(formHelpers.createElement('p', {
                className: 'excl-locked-note',
                textContent: LangUtil.EXCLUSIONS_LOCKED_NOTE,
            }));
        }

        const patterns = Array.isArray(data?.globalAllowPatterns) ? data.globalAllowPatterns : [];
        const providers = data?.providers && typeof data.providers === 'object' ? data.providers : {};

        wrapper.appendChild(buildTrustedSection(patterns, readOnly));
        wrapper.appendChild(buildBypassSection(providers, readOnly));

        if (!readOnly) {
            wrapper.appendChild(buildClearFooter());
        }
        return wrapper;
    };

    const buildErrorState = () => formHelpers.createElement('p', {
        className: 'excl-empty',
        textContent: LangUtil.EXCLUSIONS_LOAD_ERROR
    });

    const render = async runtime => {
        if (runtime) {
            currentRuntime = runtime;
        }

        const container = resolveContainer();

        if (!container) {
            console.warn("'exclusionsList' not found in SettingsPage DOM.");
            return;
        }

        const readOnly = isReadOnly();
        let data = null;

        try {
            const response = await send(messages.GET_EXCLUSIONS, {});

            if (!response?.ok) {
                throw new Error('GET_EXCLUSIONS returned an error response');
            }

            data = response.data;
        } catch (error) {
            console.error('ExclusionsPage failed to load exclusions', error);
            const errorWrapper = formHelpers.createElement('div', {className: 'exclusions'});
            errorWrapper.append(buildErrorState());
            container.replaceChildren(errorWrapper);
            return;
        }

        container.replaceChildren(buildContent(data, readOnly));

        if (pendingFocusAdd && !readOnly) {
            pendingFocusAdd = false;
            container.querySelector('.excl-add-input')?.focus();
        }
    };

    return Object.freeze({
        render,
    });
})();
