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

globalThis.OspreyFormHelpers = (() => {
    // Global variables
    const customProviderNormalizer = globalThis.OspreyCustomProviderNormalizer;
    const toast = globalThis.OspreyToast;

    const maxProviderNameLength = 64;
    const maxAPIKeyLength = 2048;
    const maxHeadersLength = 4096;
    const maxBodyLength = 8192;
    const maxLogicRules = 10;
    const maxLogicConditionLength = 200;
    const maxHeaderLength = 20;
    const maxHeaderValueLength = 1024;

    const allResultTypes = Object.freeze([
        'MALICIOUS', 'PHISHING', 'ADULT_CONTENT', 'ALLOWED', 'KNOWN_SAFE'
    ]);

    const blockResultTypes = Object.freeze([
        'MALICIOUS', 'PHISHING', 'ADULT_CONTENT'
    ]);

    const forbiddenHeaderNames = Object.freeze([
        'accept-charset', 'accept-encoding', 'access-control-request-headers',
        'access-control-request-method', 'connection', 'content-length', 'cookie',
        'cookie2', 'date', 'dnt', 'expect', 'host', 'keep-alive', 'origin',
        'permissions-policy', 'proxy-authenticate', 'proxy-authorization', 'referer',
        'sec-fetch-dest', 'sec-fetch-mode', 'sec-fetch-site', 'sec-fetch-user',
        'sec-gpc', 'te', 'trailer', 'transfer-encoding', 'upgrade', 'via',
    ]);

    const forbiddenHeaderPrefixes = Object.freeze([
        'proxy-', 'sec-'
    ]);

    const forbiddenLogicTokens = Object.freeze([
        '__proto__', 'constructor', 'prototype', 'window', 'document', 'globalthis',
        'function', 'eval', 'import', 'fetch', 'xmlhttprequest', 'chrome', 'browser',
        'this', 'new ', '=>', ';', '`', '{', '}', '[', ']',
    ]);

    const directProps = Object.freeze([
        'id', 'className', 'type', 'textContent', 'value',
        'placeholder', 'rows', 'title', 'href', 'target', 'rel', 'src', 'alt',
        'tabIndex', 'autocomplete'
    ]);

    const boolProps = Object.freeze([
        'disabled', 'hidden', 'spellcheck', 'readOnly'
    ]);

    const ariaMap = Object.freeze({
        ariaLabel: 'aria-label',
        ariaChecked: 'aria-checked',
        ariaExpanded: 'aria-expanded',
        ariaPressed: 'aria-pressed',
    });

    const allowedLogicConditionPattern = /^[A-Za-z0-9\s._'"!=<>&|:/+,()%\-]+$/;
    const responseRefLogicConditionPattern = /\bresponse(?:\.[A-Za-z_$][\w$]*)+/;

    function invalid(error) {
        return {ok: false, error};
    }

    function valid(value) {
        return {ok: true, value};
    }

    function createElement(tagName, options, ...children) {
        options = options || {};
        const element = document.createElement(tagName);

        for (const prop of directProps) {
            if (options[prop] !== undefined) {
                element[prop] = options[prop];
            }
        }

        for (const prop of boolProps) {
            if (options[prop] !== undefined) {
                element[prop] = Boolean(options[prop]);
            }
        }

        if (options.role !== undefined) {
            element.setAttribute('role', options.role);
        }

        for (const [prop, attr] of Object.entries(ariaMap)) {
            if (options[prop] !== undefined) {
                element.setAttribute(attr, String(options[prop]));
            }
        }

        for (const [name, value] of Object.entries(options.dataset || {})) {
            if (value !== undefined && value !== null) {
                element.dataset[name] = String(value);
            }
        }

        for (const [name, value] of Object.entries(options.attributes || {})) {
            if (value !== undefined && value !== null) {
                element.setAttribute(name, String(value));
            }
        }

        for (const child of children.flat(Infinity)) {
            if (child === null || child === undefined || child === false) {
                continue;
            }

            element.append(child instanceof Node ? child : document.createTextNode(String(child)));
        }
        return element;
    }

    function createClassElement(tagName, className, ...children) {
        return createElement(tagName, {className}, ...children);
    }

    function createTextElement(tagName, className, textContent) {
        return createElement(tagName, {className, textContent});
    }

    function appendOptions(select, optionValues, selectedValue, getLabel = value => value) {
        for (const optionValue of optionValues) {
            const option = createElement('option', {
                value: optionValue,
                textContent: getLabel(optionValue)
            });

            option.selected = selectedValue === optionValue;
            select.appendChild(option);
        }
    }

    function createLogicButton(className, textContent, handler) {
        const button = createElement('button', {
            type: 'button',
            className,
            textContent
        });

        button.addEventListener('click', handler);
        return button;
    }

    function sanitizeSingleLine(value, maxLength = 256) {
        return String(value ?? '')
            .replaceAll(/[\u0000-\u001F\u007F]+/g, ' ')
            .replaceAll(/\s+/g, ' ')
            .trim()
            .slice(0, maxLength);
    }

    function sanitizeMultiline(value, maxLength = 4096) {
        return String(value ?? '')
            .replaceAll(/\r\n?/g, '\n')
            .replaceAll('\u0000', '')
            .trim()
            .slice(0, maxLength);
    }

    function normalizeProviderName(value) {
        return sanitizeSingleLine(value, maxProviderNameLength);
    }

    function normalizeApiKey(value) {
        return sanitizeMultiline(value, maxAPIKeyLength);
    }

    function isPrivateOrLocalHostname(hostname) {
        const value = String(hostname ?? '').trim().toLowerCase();

        if (!value) {
            return true;
        }

        if (value === 'localhost' || value === '::1' || value.endsWith('.localhost') ||
            value.endsWith('.local') || value.endsWith('.internal') || value.endsWith('.home')) {
            return true;
        }

        if (value.startsWith('127.') || value.startsWith('10.') ||
            value.startsWith('192.168.') || value.startsWith('169.254.')) {
            return true;
        }

        const octetMatch = /^172\.(\d{1,3})\./.exec(value);

        if (octetMatch) {
            const n = Number.parseInt(octetMatch[1], 10);

            if (n >= 16 && n <= 31) {
                return true;
            }
        }
        return /^(0\.0\.0\.0|255\.255\.255\.255)$/.test(value) || /^(fc|fd|fe80):/i.test(value);
    }

    function normalizePublicHttpsUrl(value) {
        const rawValue = sanitizeSingleLine(value, 2048);

        if (!rawValue) {
            return invalid(LangUtil.ERROR_API_URL_REQUIRED);
        }

        let parsed;

        try {
            parsed = new URL(rawValue);
        } catch {
            return invalid(LangUtil.ERROR_API_URL_INVALID);
        }

        if (parsed.protocol !== 'https:') {
            return invalid(LangUtil.ERROR_API_URL_HTTPS);
        }

        if (!parsed.hostname || isPrivateOrLocalHostname(parsed.hostname)) {
            return invalid(LangUtil.ERROR_API_URL_PRIVATE);
        }

        if (parsed.username || parsed.password) {
            return invalid(LangUtil.ERROR_API_URL_CREDENTIALS);
        }

        parsed.hash = '';
        return valid(parsed.toString());
    }

    function normalizeRequestHeaders(value) {
        const rawValue = sanitizeMultiline(value, maxHeadersLength);

        if (!rawValue) {
            return valid('');
        }

        const rawLines = rawValue.split('\n').map(line => line.trim()).filter(Boolean);

        if (rawLines.length > maxHeaderLength) {
            return invalid(LangUtil.format('errorHeadersTooMany', String(maxHeaderLength)));
        }

        const normalizedLines = [];

        for (const line of rawLines) {
            const sep = line.indexOf(':');

            if (sep <= 0) {
                return invalid(LangUtil.ERROR_HEADER_FORMAT);
            }

            const name = sanitizeSingleLine(line.slice(0, sep), 128);
            const val = sanitizeSingleLine(line.slice(sep + 1), maxHeaderValueLength);
            const lower = name.toLowerCase();

            if (!/^[A-Za-z0-9-]+$/.test(name)) {
                return invalid(LangUtil.format('errorHeaderInvalidName', name));
            }

            if (forbiddenHeaderNames.includes(lower) || forbiddenHeaderPrefixes.some(prefix => lower.startsWith(prefix))) {
                return invalid(LangUtil.format('errorHeaderForbiddenName', name));
            }

            normalizedLines.push(`${name}: ${val}`);
        }
        return valid(normalizedLines.join('\n'));
    }

    function normalizeJsonTemplate(value) {
        const rawValue = sanitizeMultiline(value, maxBodyLength);

        if (!rawValue) {
            return valid('');
        }

        const safe = rawValue
            .replaceAll('{url}', 'https://example.invalid/')
            .replaceAll('{hostname}', 'example.invalid')
            .replaceAll('{api_key}', 'api-key');

        try {
            JSON.parse(safe);
        } catch {
            return invalid(LangUtil.ERROR_REQUEST_BODY_INVALID_JSON);
        }
        return valid(rawValue);
    }

    function normalizeLogicCondition(value) {
        const condition = sanitizeSingleLine(value, maxLogicConditionLength);

        if (!condition) {
            return invalid(LangUtil.ERROR_RULE_CONDITION_EMPTY);
        }

        if (!allowedLogicConditionPattern.test(condition)) {
            return invalid(LangUtil.ERROR_RULE_CONDITION_UNSUPPORTED);
        }

        if (!responseRefLogicConditionPattern.test(condition)) {
            return invalid(LangUtil.ERROR_RULE_CONDITION_RESPONSE_REF);
        }

        const lower = condition.toLowerCase();

        for (const token of forbiddenLogicTokens) {
            if (lower.includes(token)) {
                return invalid(LangUtil.format('errorRuleConditionForbiddenToken', token.trim()));
            }
        }
        return valid(condition);
    }

    function normalizeLogicBlocks(rules) {
        const rawRules = Array.isArray(rules) ? rules : [];

        if (rawRules.length > maxLogicRules) {
            return invalid(LangUtil.format('errorRulesTooMany', String(maxLogicRules)));
        }

        const normalized = [];

        for (const rawRule of rawRules) {
            const resultType = blockResultTypes.includes(rawRule?.resultType) ? rawRule.resultType : 'MALICIOUS';
            const normalizedCondition = normalizeLogicCondition(rawRule?.condition ?? '');

            if (!normalizedCondition.ok) {
                return normalizedCondition;
            }

            normalized.push({
                condition: normalizedCondition.value,
                resultType
            });
        }
        return valid(normalized);
    }

    function normalizeCustomProviderInput(rawProvider, options = {}) {
        const logValidationFailures = options.logValidationFailures === true;

        const providerId = sanitizeSingleLine(rawProvider?.id ?? options.providerId ?? '', 128) ||
            options.providerId || customProviderNormalizer.generateId();

        const name = normalizeProviderName(rawProvider?.name ?? '');
        const normalizedUrl = normalizePublicHttpsUrl(rawProvider?.apiUrl ?? '');

        if (!normalizedUrl.ok) {
            return normalizedUrl;
        }

        const requestHeaders = normalizeRequestHeaders(rawProvider?.requestHeaders ?? '');
        const requestBody = normalizeJsonTemplate(rawProvider?.requestBody ?? '');
        const logicBlocks = normalizeLogicBlocks(rawProvider?.logicBlocks ?? []);

        if (!requestHeaders.ok) {
            return requestHeaders;
        }

        if (!requestBody.ok) {
            return requestBody;
        }

        if (!logicBlocks.ok) {
            return logicBlocks;
        }

        const normalized = {
            id: providerId,
            name,
            apiUrl: normalizedUrl.value,
            method: String(rawProvider?.method ?? 'GET').toUpperCase() === 'POST' ? 'POST' : 'GET',
            apiKey: normalizeApiKey(rawProvider?.apiKey ?? ''),
            requestHeaders: requestHeaders.value,
            requestBody: requestBody.value,
            logicBlocks: logicBlocks.value,
        };

        if (!normalized.name) {
            return invalid(LangUtil.ERROR_PROVIDER_NAME_REQUIRED);
        }

        try {
            const definition = customProviderNormalizer.normalize(normalized);
            customProviderNormalizer.validate(definition);
        } catch (e) {
            if (logValidationFailures) {
                console.warn(`OspreyFormHelpers rejected normalized custom provider '${providerId}': ${e.message || 'validation failed'}`);
            }
            return invalid(e.message || 'The provider definition was rejected.');
        }
        return valid(normalized);
    }

    function createFieldGroup(labelText, inputElement, tagNode = null, helpNode = null) {
        const label = createTextElement('label', 'field-label', labelText);

        if (tagNode) {
            label.append(' ', tagNode);
        }
        return createClassElement('div', 'field-group', label, helpNode, inputElement);
    }

    function createFieldHelp(text) {
        return createTextElement('div', 'field-help', text);
    }

    function createTag(text, className) {
        return createTextElement('span', className, text);
    }

    function createOptionalTag(text) {
        return createTag(text, 'optional-tag');
    }

    function createRequiredTag(text) {
        return createTag(text, 'required-tag');
    }

    function createReadOnlyInput(value) {
        return createElement('input', {
            className: 'field-input',
            type: 'text',
            value: sanitizeSingleLine(value, 2048),
            disabled: true,
            readOnly: true,
            spellcheck: false,
        });
    }

    function createEditableField(tagName, options, defaults) {
        return createElement(tagName, {
            ...defaults,
            ...options,
            value: options.value ?? '',
            placeholder: options.placeholder,
            spellcheck: false,
            autocomplete: options.autocomplete ?? 'off',
            dataset: options.dataset,
        });
    }

    function createEditableInput(options) {
        return createEditableField('input', options, {
            className: 'field-input field-enabled',
            type: options.type ?? 'text'
        });
    }

    function createEditableTextArea(options) {
        return createEditableField('textarea', options, {
            className: 'field-textarea field-enabled',
            rows: options.rows ?? 3
        });
    }

    function createMethodSelect(method, dataset) {
        const select = createElement('select', {
            className: 'field-select field-enabled',
            dataset
        });

        appendOptions(select, ['GET', 'POST'], method);
        return select;
    }

    function createPasswordField(inputOptions) {
        const wrapper = createClassElement('div', 'password-field-wrap');

        const input = createEditableInput({
            ...inputOptions,
            type: 'password',
            autocomplete: 'new-password'
        });

        const revealButton = createElement('button', {
            type: 'button',
            className: 'password-reveal-btn',
            ariaLabel: LangUtil.SHOW_API_KEY,
            ariaPressed: false,
        }, createClassElement('span', 'eye-icon eye-closed'));

        revealButton.addEventListener('click', event => {
            event.stopPropagation();

            const isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';
            revealButton.setAttribute('aria-label', isHidden ? LangUtil.HIDE_API_KEY : LangUtil.SHOW_API_KEY);
            revealButton.setAttribute('aria-pressed', String(isHidden));

            const icon = revealButton.querySelector('.eye-icon');

            if (icon) {
                icon.classList.toggle('eye-closed', !isHidden);
                icon.classList.toggle('eye-open', isHidden);
            }
        });

        wrapper.append(input, revealButton);
        return {wrapper, input};
    }

    function updateLogicRowIndices(blockList) {
        blockList.querySelectorAll('.logic-block').forEach((row, index) => {
            row.dataset.index = String(index);
        });
    }

    function readLogicBlocks(root) {
        const rules = [];

        for (const row of root.querySelectorAll('.logic-block')) {
            const condition = row.querySelector('.logic-condition')?.value ?? '';
            const resultType = row.querySelector('.logic-result')?.value ?? 'MALICIOUS';

            if (String(condition).trim()) {
                rules.push({condition, resultType});
            }
        }
        return rules;
    }

    function createLogicBlockRow(rule, onChange) {
        const row = createClassElement('div', 'logic-block');
        const inner = createClassElement('div', 'logic-block-inner');

        const conditionInput = createEditableInput({
            value: rule.condition ?? '',
            placeholder: 'response.result === "phishing"',
            dataset: {
                logicField: 'condition'
            },
        });

        conditionInput.classList.add('logic-condition');

        const conditionError = createClassElement('span', 'logic-condition-error');

        function syncConditionError() {
            const v = normalizeLogicCondition(conditionInput.value);
            const hasValue = conditionInput.value.trim().length > 0;
            conditionInput.classList.toggle('is-invalid', !v.ok && hasValue);
            conditionError.textContent = !v.ok && hasValue ? v.error : '';
        }

        const resultSelect = createElement('select', {
            className: 'field-select field-enabled logic-result',
            dataset: {
                logicField: 'result'
            },
        });

        appendOptions(resultSelect, blockResultTypes, rule.resultType ?? 'MALICIOUS', LangUtil.resultLabel);

        const buttonGroup = createClassElement('div', 'logic-block-btns');

        const syncList = () => {
            updateLogicRowIndices(row.parentElement);
            onChange();
        };

        buttonGroup.append(
            createLogicButton('logic-move-btn', '▲', () => {
                const previous = row.previousElementSibling;

                if (previous) {
                    previous.before(row);
                    syncList();
                }
            }),

            createLogicButton('logic-move-btn', '▼', () => {
                const next = row.nextElementSibling;

                if (next && row.parentElement) {
                    row.parentElement.insertBefore(next, row);
                    syncList();
                }
            }),

            createLogicButton('logic-remove-btn', '✕', () => {
                const list = row.parentElement;
                row.remove();

                if (list) {
                    updateLogicRowIndices(list);
                }

                onChange();
            })
        );

        conditionInput.addEventListener('input', () => {
            syncConditionError();
            onChange();
        });

        resultSelect.addEventListener('change', onChange);
        syncConditionError();

        inner.append(
            createTextElement('span', 'logic-block-label', LangUtil.LOGIC_IF_LABEL),
            conditionInput,
            createTextElement('span', 'logic-block-label', LangUtil.LOGIC_RETURN_LABEL),
            resultSelect,
            buttonGroup,
        );

        row.append(inner, conditionError);
        return row;
    }

    function createLogicBlockEditor(rules, onChange) {
        const fieldGroup = createClassElement('div', 'field-group');
        const header = createClassElement('div', 'logic-header');
        const label = createTextElement('label', 'field-label', LangUtil.FIELD_LABEL_BLOCK_LOGIC);
        const help = createFieldHelp(LangUtil.TAG_BLOCK_LOGIC_HINT);
        const addButton = createTextElement('button', 'logic-add-btn', LangUtil.ADD_RULE_BUTTON);
        const blockList = createClassElement('div', 'logic-block-list');

        addButton.type = 'button';

        const syncEditor = () => {
            updateLogicRowIndices(blockList);
            onChange();
        };

        addButton.addEventListener('click', () => {
            if (blockList.querySelectorAll('.logic-block').length >= maxLogicRules) {
                toast.show(LangUtil.format('toastMaxLogicRules', String(maxLogicRules)), true);
                return;
            }

            blockList.appendChild(createLogicBlockRow({
                condition: '',
                resultType: 'MALICIOUS'
            }, syncEditor));

            syncEditor();
        });

        for (const rule of Array.isArray(rules) ? rules : []) {
            blockList.appendChild(createLogicBlockRow(rule, syncEditor));
        }

        header.append(label, addButton);
        fieldGroup.append(header, help, blockList);
        updateLogicRowIndices(blockList);
        return fieldGroup;
    }

    // Public API
    return Object.freeze({
        maxAPIKeyLength,
        maxHeadersLength,
        maxBodyLength,
        blockResultTypes,
        allResultTypes,
        createElement,
        sanitizeSingleLine,
        sanitizeMultiline,
        normalizeProviderName,
        normalizeApiKey,
        normalizePublicHttpsUrl,
        normalizeRequestHeaders,
        normalizeJsonTemplate,
        normalizeLogicCondition,
        normalizeLogicBlocks,
        normalizeCustomProviderInput,
        createFieldGroup,
        createFieldHelp,
        createOptionalTag,
        createRequiredTag,
        createReadOnlyInput,
        createEditableInput,
        createEditableTextArea,
        createMethodSelect,
        createPasswordField,
        readLogicBlocks,
        createLogicBlockEditor,
    });
})();
