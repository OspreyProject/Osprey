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

globalThis.OspreyProviderList = (() => {
    // Global variables
    const formHelpers = globalThis.OspreyFormHelpers;
    const providerCard = globalThis.OspreyProviderCard;
    const providerCatalog = globalThis.OspreyProviderCatalog;
    const providerStateStore = globalThis.OspreyProviderStateStore;
    const toast = globalThis.OspreyToast;
    const timer = globalThis.OspreyTimer;

    const emitSettingsChanged = () => document.dispatchEvent(new CustomEvent('osprey:settings-changed'));

    function runStoreAction(promise, successMessage, errorMessage) {
        promise.then(() => {
            toast.show(successMessage);
            emitSettingsChanged();
        }).catch(error => {
            console.error(errorMessage, error);
            toast.show(LangUtil.TOAST_FAILED_TO_SAVE, true);
        });
    }

    function createSection(title, items, extraHeaderControl = null) {
        const section = formHelpers.createElement('div', {
            className: 'provider-section'
        });

        section.appendChild(extraHeaderControl || formHelpers.createElement('p', {
            className: 'section-label providers-label',
            textContent: title
        }));

        const inner = formHelpers.createElement('div', {
            className: 'provider-list-inner'
        });

        for (const item of items) {
            inner.appendChild(item);
        }

        section.appendChild(inner);

        return {
            section,
            inner
        };
    }

    function createResetFooter(runtime = null) {
        const footer = formHelpers.createElement('div', {
            className: 'reset-footer'
        });

        const resetProvidersDisabled = Boolean(runtime?.effectiveState?.app?.disableResetButtons ||
            runtime?.effectiveState?.app?.lockSettings);

        const resetProvidersButton = formHelpers.createElement('button', {
            id: 'resetDefaultProvidersBtn',
            type: 'button',
            className: 'reset-btn reset-providers-btn',
            textContent: LangUtil.RESET_DEFAULT_PROVIDERS,
            disabled: resetProvidersDisabled
        });

        const resetAllButton = formHelpers.createElement('button', {
            id: 'resetAllBtn',
            type: 'button',
            className: 'reset-btn reset-all-btn',
            textContent: LangUtil.RESET_ALL,
            disabled: resetProvidersDisabled
        });

        resetProvidersButton.addEventListener('click', () => {
            runStoreAction(
                providerStateStore.resetDefaultProviders(),
                LangUtil.TOAST_DEFAULT_PROVIDERS_RESTORED,
                'ProviderList failed to reset default providers'
            );
        });

        resetAllButton.addEventListener('click', () => {
            runStoreAction(
                providerStateStore.resetAll(),
                LangUtil.TOAST_ALL_SETTINGS_RESTORED,
                'ProviderList failed to reset all settings'
            );
        });

        footer.append(resetProvidersButton, resetAllButton);
        return footer;
    }

    function render(state, runtime = null) {
        const container = document.getElementById('providerList');

        if (!container) {
            console.warn("'providerList' not found in SettingsPage DOM.");
            return;
        }

        const definitions = providerCatalog.getAllDefinitions();

        const getProviderState = id => state.providers?.[id] || {
            enabled: false,
            apiKey: ''
        };

        const fragment = document.createDocumentFragment();
        const builtIns = definitions.filter(d => d.kind === 'proxy_builtin');
        const thirdParty = definitions.filter(d => d.kind === 'direct_static');

        fragment.appendChild(createSection(
            LangUtil.PROVIDERS_SECTION,
            builtIns.map(def => providerCard.buildProviderCard(def, getProviderState(def.id), runtime))
        ).section);

        const thirdPartySection = createSection(
            LangUtil.THIRD_PARTY_SECTION,
            thirdParty.length > 0 ? thirdParty.map(def => providerCard.buildProviderCard(def, getProviderState(def.id), runtime)) : []
        );

        thirdPartySection.section.classList.add('integrations-section');
        fragment.appendChild(thirdPartySection.section);
        fragment.appendChild(createResetFooter(runtime));
        container.replaceChildren(fragment);
    }

    // Public API
    return timer.instrument('OspreyProviderList', {
        render
    });
})();
