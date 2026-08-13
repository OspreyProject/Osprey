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

globalThis.OspreyProviderList = (() => {
    const formHelpers = globalThis.OspreyFormHelpers;
    const providerCard = globalThis.OspreyProviderCard;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const toast = globalThis.OspreyToast;

    const defaultProviderState = Object.freeze({
        enabled: false,
        apiKey: '',
    });

    let cachedContainer = null;
    let isEventDelegationBound = false;

    const emitSettingsChanged = () => document.dispatchEvent(new CustomEvent('osprey:settings-changed'));

    function runStoreAction(promise, successMessage, errorMessage, successIsError = false) {
        return promise.then(() => {
            toast.show(successMessage, successIsError);
            emitSettingsChanged();
        }).catch(error => {
            console.error(errorMessage, error);
            toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
        });
    }

    function handleDelegatedAction(event) {
        const target = event.target;

        if (target.disabled || !target.classList.contains('reset-btn')) {
            return;
        }

        if (target.id === 'resetDefaultProvidersBtn') {
            runStoreAction(
                providerStateStore.resetDefaultProviders(),
                LangUtil.TOAST_DEFAULT_PROVIDERS_RESTORED,
                'ProviderList failed to reset default providers',
            );
        } else if (target.id === 'resetAllBtn') {
            runStoreAction(
                providerStateStore.resetAll(),
                LangUtil.TOAST_ALL_SETTINGS_RESTORED,
                'ProviderList failed to reset all settings',
            );
        }
    }

    function createMasterDisableRow(state, runtime) {
        const isDisabledAll = Boolean(state?.app?.disableAllProviders);
        const locked = Boolean(runtime?.effectiveState?.app?.lockProviderSettings);

        const row = formHelpers.createElement('div', {
            className: 'master-disable-row',
        });

        const label = formHelpers.createElement('span', {
            className: 'master-disable-label',
            textContent: LangUtil.MASTER_DISABLE_ALL,
        });

        const toggle = formHelpers.createElement('span', {
            className: isDisabledAll ? 'toggle-switch on' : 'toggle-switch off',
            role: 'switch',
            ariaChecked: isDisabledAll,
            tabIndex: locked ? -1 : 0,
            ariaLabel: LangUtil.MASTER_DISABLE_ALL,
        });

        if (locked) {
            toggle.classList.add('disabled');
            toggle.setAttribute('aria-disabled', 'true');
        }

        const activate = () => {
            if (locked) {
                return;
            }

            const next = !toggle.classList.contains('on');

            runStoreAction(
                providerStateStore.setDisableAllProviders(next),
                next ? LangUtil.TOAST_ALL_PROVIDERS_DISABLED : LangUtil.TOAST_ALL_PROVIDERS_ENABLED,
                'ProviderList failed to update disable-all state',
                next,
            );
        };

        toggle.addEventListener('click', activate);

        toggle.addEventListener('keydown', event => {
            if (event.key === 'Enter' || event.key === ' ') {
                event.preventDefault();
                activate();
            }
        });

        row.append(label, toggle);
        return row;
    }

    function createSection(title, items, extraHeaderControl = null) {
        const section = formHelpers.createElement('div', {
            className: 'provider-section',
        });

        section.appendChild(extraHeaderControl || formHelpers.createElement('p', {
            className: 'section-label providers-label',
            textContent: title,
        }));

        const inner = formHelpers.createElement('div', {
            className: 'provider-list-inner',
        });

        for (let i = 0, len = items.length; i < len; i++) {
            inner.appendChild(items[i]);
        }

        section.appendChild(inner);

        return {
            section,
            inner,
        };
    }

    function createResetFooter(runtime = null) {
        const footer = formHelpers.createElement('div', {
            className: 'reset-footer',
        });

        const appState = runtime?.effectiveState?.app;
        const resetProvidersDisabled = Boolean(appState?.disableSettingsReset || appState?.lockProviderSettings);

        const resetRow = formHelpers.createElement('div', {
            className: 'reset-footer-row',
        });

        const resetProvidersButton = formHelpers.createElement('button', {
            id: 'resetDefaultProvidersBtn',
            type: 'button',
            className: 'reset-btn reset-providers-btn',
            textContent: LangUtil.RESET_DEFAULT_PROVIDERS,
            disabled: resetProvidersDisabled,
        });

        const resetAllButton = formHelpers.createElement('button', {
            id: 'resetAllBtn',
            type: 'button',
            className: 'reset-btn reset-all-btn',
            textContent: LangUtil.RESET_ALL,
            disabled: resetProvidersDisabled,
        });

        resetRow.append(resetProvidersButton, resetAllButton);
        footer.append(resetRow);

        const importExportPage = globalThis.OspreyImportExportPage;

        if (importExportPage) {
            footer.append(importExportPage.buildControls(runtime));
        }
        return footer;
    }

    function render(state, runtime = null) {
        let container = cachedContainer;

        if (!container?.isConnected) {
            container = document.getElementById('providerList');
            cachedContainer = container;
            isEventDelegationBound = false;
        }

        if (!container) {
            console.warn("'providerList' not found in SettingsPage DOM.");
            return;
        }

        if (!isEventDelegationBound) {
            container.addEventListener('click', handleDelegatedAction);
            isEventDelegationBound = true;
        }

        const definitions = providerCatalog.getAllDefinitions();
        const providersState = state.providers;

        const builtIns = [];
        const thirdParty = [];

        for (let i = 0, len = definitions.length; i < len; i++) {
            const def = definitions[i];

            if (def.kind === 'proxy_builtin') {
                builtIns.push(def);
            } else if (def.kind === 'direct_static') {
                thirdParty.push(def);
            }
        }

        const fragment = document.createDocumentFragment();
        const masterDisabled = Boolean(state.app?.disableAllProviders);

        fragment.appendChild(createMasterDisableRow(state, runtime));

        const builtInLength = builtIns.length;
        const builtInItems = Array.from({length: builtInLength});

        for (let i = 0; i < builtInLength; i++) {
            const def = builtIns[i];
            const pState = providersState?.[def.id] || defaultProviderState;
            builtInItems[i] = providerCard.buildProviderCard(def, pState, runtime);
        }

        const builtInSection = createSection(
            LangUtil.PROVIDERS_SECTION,
            builtInItems,
        );

        if (masterDisabled) {
            builtInSection.inner.classList.add('providers-locked');
        }

        fragment.appendChild(builtInSection.section);

        const thirdPartyLength = thirdParty.length;
        const thirdPartyItems = Array.from({length: thirdPartyLength});

        if (thirdPartyLength > 0) {
            for (let i = 0; i < thirdPartyLength; i++) {
                const def = thirdParty[i];
                const pState = providersState?.[def.id] || defaultProviderState;
                thirdPartyItems[i] = providerCard.buildProviderCard(def, pState, runtime);
            }
        }

        const thirdPartySection = createSection(
            LangUtil.THIRD_PARTY_SECTION,
            thirdPartyItems,
        );

        if (masterDisabled) {
            thirdPartySection.inner.classList.add('providers-locked');
        }

        thirdPartySection.section.classList.add('integrations-section');
        fragment.appendChild(thirdPartySection.section);
        fragment.appendChild(createResetFooter(runtime));

        container.replaceChildren(fragment);
    }

    return Object.freeze({
        render,
    });
})();
