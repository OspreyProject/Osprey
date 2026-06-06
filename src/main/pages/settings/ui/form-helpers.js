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
    const timer = globalThis.OspreyTimer;

    const maxProviderNameLength = 64;
    const maxAPIKeyLength = 2048;

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

    function createFieldGroup(labelText, inputElement, tagNode = null, helpNode = null) {
        const label = createTextElement('label', 'field-label', labelText);

        if (tagNode) {
            label.append(' ', tagNode);
        }
        return createClassElement('div', 'field-group', label, helpNode, inputElement);
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

    // Public API
    return timer.instrument('OspreyFormHelpers', {
        maxAPIKeyLength,
        createElement,
        sanitizeSingleLine,
        sanitizeMultiline,
        normalizeProviderName,
        normalizeApiKey,
        createFieldGroup,
        createReadOnlyInput,
        createPasswordField,
    });
})();
