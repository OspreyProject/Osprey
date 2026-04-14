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

    const persistCustomProviders = (mutator, additionalProviderStates = {}) => globalThis.OspreyProviderStateStore.getState().then(state => {
        const currentProviders = Object.values(state.customProviders || {});
        const nextProviders = mutator(currentProviders.slice(), state) || currentProviders;
        return globalThis.OspreyProviderStateStore.setCustomProviders(nextProviders, additionalProviderStates);
    });

    const createDefaultLogicBlocks = () => [{
        condition: '',
        resultType: 'Malicious'
    }];

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

    function addSyncListeners(fields, listener) {
        for (const field of fields) {
            field.addEventListener('input', listener);
            field.addEventListener('change', listener);
        }
    }

    function setDisabled(fields, disabled) {
        for (const field of fields) {
            field.disabled = disabled;
        }
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

    function createAddProviderForm(toggleButton, runtime = null) {
        const form = formHelpers.createElement('div', {
            id: 'addProviderForm',
            className: 'add-provider-form',
            hidden: true
        });

        const nameInput = formHelpers.createEditableInput({
            value: '',
            dataset: {
                add: 'name'
            }
        });

        const apiUrlInput = formHelpers.createEditableInput({
            value: '',
            placeholder: 'https://api.example.com/check',
            dataset: {
                add: 'apiUrl'
            }
        });

        const methodSelect = formHelpers.createMethodSelect('GET', {
            add: 'method'
        });

        const passwordField = formHelpers.createPasswordField({
            value: '',
            dataset: {
                add: 'apiKey'
            }
        });

        const requestHeaders = formHelpers.createEditableTextArea({
            value: 'X-API-Key: {api_key}',
            dataset: {
                add: 'requestHeaders'
            }
        });

        const requestBody = formHelpers.createEditableTextArea({
            value: '{"url": "{url}"}',
            dataset: {
                add: 'requestBody'
            }
        });

        const addButton = formHelpers.createElement('button', {
            id: 'addProviderBtn',
            type: 'button',
            className: 'action-btn apply-btn',
            textContent: LangUtil.ADD_PROVIDER_BUTTON,
            disabled: true
        });

        const fields = [nameInput, apiUrlInput, methodSelect, passwordField.input, requestHeaders, requestBody];

        function readCandidateProvider(id = 'custom_candidate') {
            return {
                id,
                name: nameInput.value,
                apiUrl: apiUrlInput.value,
                method: methodSelect.value,
                apiKey: passwordField.input.value,
                requestHeaders: requestHeaders.value,
                requestBody: requestBody.value,
                logicBlocks: formHelpers.readLogicBlocks(form)
            };
        }

        function syncAddButtonState() {
            const normalized = formHelpers.normalizeCustomProviderInput(readCandidateProvider(), {
                providerId: 'custom_candidate'
            });

            addButton.disabled = !normalized.ok;
            addButton.classList.toggle('is-valid', normalized.ok);
        }

        let logicEditor = formHelpers.createLogicBlockEditor(createDefaultLogicBlocks(), syncAddButtonState);

        function resetAddProviderForm() {
            nameInput.value = '';
            apiUrlInput.value = '';
            methodSelect.value = 'GET';
            passwordField.input.value = '';
            requestHeaders.value = 'X-API-Key: {api_key}';
            requestBody.value = '{"url": "{url}"}';

            const freshLogicEditor = formHelpers.createLogicBlockEditor(createDefaultLogicBlocks(), syncAddButtonState);
            logicEditor.replaceWith(freshLogicEditor);
            logicEditor = freshLogicEditor;
            syncAddButtonState();
        }

        addSyncListeners(fields, syncAddButtonState);

        addButton.addEventListener('click', () => {
            if (addButton.disabled) {
                return;
            }

            const normalized = formHelpers.normalizeCustomProviderInput(
                readCandidateProvider(providerStateStore.generateCustomProviderId())
            );

            if (!normalized.ok) {
                console.warn(`ProviderList rejected custom provider creation: ${normalized.error}`);
                toast.show(normalized.error, true);
                return;
            }

            runStoreAction(
                persistCustomProviders(existing => [...existing, normalized.value], {
                    [normalized.value.id]: {enabled: true}
                }),
                LangUtil.TOAST_PROVIDER_ADDED,
                `ProviderList failed to create custom provider '${normalized.value.id}'`
            );
        });

        toggleButton.addEventListener('click', () => {
            if (form.hidden) {
                form.hidden = false;
                toggleButton.textContent = LangUtil.CANCEL_ADD_PROVIDER;
                return;
            }

            resetAddProviderForm();
            form.hidden = true;
            toggleButton.textContent = LangUtil.ADD_PROVIDER_TOGGLE;
        });

        form.append(
            formHelpers.createElement('p', {
                className: 'add-provider-title',
                textContent: LangUtil.NEW_PROVIDER
            }),

            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_NAME, nameInput, formHelpers.createRequiredTag('*')),
            formHelpers.createFieldGroup(LangUtil.FIELD_LABEL_API_URL, apiUrlInput, formHelpers.createRequiredTag('*')),

            formHelpers.createElement('div', {
                    className: 'field-row'
                }, formHelpers.createElement('div', {
                    className: 'field-group field-half'
                }, formHelpers.createElement('label', {
                    className: 'field-label',
                    textContent: LangUtil.FIELD_LABEL_METHOD
                }), methodSelect), formHelpers.createElement('div', {
                    className: 'field-group field-half'
                }, formHelpers.createElement('label', {
                    className: 'field-label',
                    textContent: LangUtil.FIELD_LABEL_API_KEY
                }), passwordField.wrapper)
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

            formHelpers.createElement('div', {
                className: 'add-provider-actions'
            }, addButton)
        );

        const customProvidersDisabled = Boolean(runtime?.effectiveState?.app?.disableCustomProviders ||
            runtime?.effectiveState?.app?.lockSettings);

        if (customProvidersDisabled) {
            form.hidden = true;
            toggleButton.disabled = true;
            setDisabled(fields, true);
            addButton.disabled = true;
        }

        syncAddButtonState();
        return form;
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

        const definitions = providerCatalog.getAllDefinitions(state);

        const getProviderState = id => state.providers?.[id] || {
            enabled: false,
            apiKey: ''
        };

        const fragment = document.createDocumentFragment();
        const builtIns = definitions.filter(d => d.kind === 'proxy_builtin');
        const thirdParty = definitions.filter(d => d.kind === 'direct_static');
        const customProviders = definitions.filter(d => d.kind === 'direct_custom');

        const customProvidersDisabled = Boolean(runtime?.effectiveState?.app?.disableCustomProviders ||
            runtime?.effectiveState?.app?.lockSettings || state.app?.disableCustomProviders || state.app?.lockSettings);

        fragment.appendChild(createSection(
            LangUtil.PROVIDERS_SECTION,
            builtIns.map(def => providerCard.buildProviderCard(def, getProviderState(def.id), state, runtime))
        ).section);

        const thirdPartySection = createSection(
            LangUtil.THIRD_PARTY_SECTION,
            thirdParty.length > 0 ? thirdParty.map(def => providerCard.buildProviderCard(def, getProviderState(def.id), state, runtime)) : []
        );

        thirdPartySection.section.classList.add('integrations-section');
        fragment.appendChild(thirdPartySection.section);

        const customHeader = formHelpers.createElement('div', {
                className: 'section-header'
            }, formHelpers.createElement('p', {
                className: 'section-label providers-label',
                textContent: LangUtil.CUSTOM_PROVIDERS_SECTION
            }), formHelpers.createElement('button', {
                id: 'toggleAddProviderForm',
                type: 'button',
                className: 'add-provider-toggle',
                textContent: LangUtil.ADD_PROVIDER_TOGGLE,
                disabled: customProvidersDisabled
            })
        );

        const customSection = createSection(LangUtil.CUSTOM_PROVIDERS_SECTION, [], customHeader);
        customSection.section.classList.add('custom-section');

        const toggleButton = customHeader.querySelector('#toggleAddProviderForm');
        const addProviderForm = createAddProviderForm(toggleButton, runtime);
        customSection.section.insertBefore(addProviderForm, customSection.inner);
        customSection.inner.id = 'customProviderList';

        if (customProviders.length > 0) {
            for (const def of customProviders) {
                customSection.inner.appendChild(providerCard.buildProviderCard(def, getProviderState(def.id), state));
            }
        } else {
            customSection.inner.appendChild(formHelpers.createElement('p', {
                className: 'no-custom-note',
                textContent: LangUtil.NO_CUSTOM_PROVIDERS
            }));
        }

        fragment.appendChild(customSection.section);
        fragment.appendChild(createResetFooter(runtime));
        container.replaceChildren(fragment);
    }

    // Public API
    return Object.freeze({
        render
    });
})();
