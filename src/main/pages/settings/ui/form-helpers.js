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

globalThis.OspreyFormHelpers = (() => {
    const maxProviderNameLength = 64;
    const maxAPIKeyLength = 2048;

    const directProps = Object.freeze([
        'id', 'className', 'type', 'textContent', 'value',
        'placeholder', 'rows', 'title', 'href', 'target', 'rel', 'src', 'alt',
        'tabIndex', 'autocomplete',
    ]);

    const boolProps = Object.freeze([
        'disabled', 'hidden', 'spellcheck', 'readOnly',
    ]);

    const ariaMap = Object.freeze({
        ariaLabel: 'aria-label',
        ariaChecked: 'aria-checked',
        ariaExpanded: 'aria-expanded',
        ariaPressed: 'aria-pressed',
    });

    const ariaKeys = Object.freeze(Object.keys(ariaMap));

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

        for (const prop of ariaKeys) {
            if (options[prop] !== undefined) {
                element.setAttribute(ariaMap[prop], String(options[prop]));
            }
        }

        if (options.dataset !== undefined) {
            const datasetKeys = Object.keys(options.dataset);

            for (const name of datasetKeys) {
                const value = options.dataset[name];

                if (value !== undefined && value !== null) {
                    element.dataset[name] = String(value);
                }
            }
        }

        if (options.attributes !== undefined) {
            const attrKeys = Object.keys(options.attributes);

            for (const name of attrKeys) {
                const value = options.attributes[name];

                if (value !== undefined && value !== null) {
                    element.setAttribute(name, String(value));
                }
            }
        }

        if (children.length > 0) {
            const flatChildren = children.flat(Infinity);

            for (const child of flatChildren) {
                if (child !== null && child !== undefined && child !== false) {
                    element.append(child instanceof Node ? child : document.createTextNode(String(child)));
                }
            }
        }
        return element;
    }

    function createClassElement(tagName, className, ...children) {
        return createElement(tagName, {className}, ...children);
    }

    function createTextElement(tagName, className, textContent) {
        return createElement(tagName, {className, textContent});
    }

    const singleLineRegex = /[\u0000-\u001F\u007F]+/g;
    const multiSpaceRegex = /\s+/g;

    function sanitizeSingleLine(value, maxLength = 256) {
        return String(value ?? '')
            .slice(0, Math.max(maxLength * 5, 8192))
            .replace(singleLineRegex, ' ')
            .replace(multiSpaceRegex, ' ')
            .trim()
            .slice(0, maxLength);
    }

    const lineBreakRegex = /\r\n?/g;
    const nullCharRegex = /\u0000/g;

    function sanitizeMultiline(value, maxLength = 4096) {
        return String(value ?? '')
            .slice(0, Math.max(maxLength * 5, 8192))
            .replace(lineBreakRegex, '\n')
            .replaceAll(nullCharRegex, '')
            .trim()
            .slice(0, maxLength);
    }

    function normalizeProviderName(value) {
        return sanitizeSingleLine(value, maxProviderNameLength);
    }

    function normalizeApiKey(value) {
        return sanitizeMultiline(value, maxAPIKeyLength);
    }

    let fieldIdCounter = 0;

    function ensureControlId(control) {
        if (!control.id) {
            fieldIdCounter += 1;
            control.id = `osprey-field-${fieldIdCounter}`;
        }
        return control.id;
    }

    function createFieldGroup(labelText, inputElement, tagNode = null, helpNode = null) {
        const label = createTextElement('label', 'field-label', labelText);

        const control = inputElement && inputElement.matches && inputElement.matches('input, textarea, select') ?
            inputElement :
            (inputElement && inputElement.querySelector ? inputElement.querySelector('input, textarea, select') : null);

        if (control) {
            label.htmlFor = ensureControlId(control);
        }

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
        const combinedOptions = {...defaults, ...options};
        combinedOptions.value = options.value ?? '';
        combinedOptions.placeholder = options.placeholder;
        combinedOptions.spellcheck = false;
        combinedOptions.autocomplete = options.autocomplete ?? 'off';
        combinedOptions.dataset = options.dataset;
        return createElement(tagName, combinedOptions);
    }

    function createEditableInput(options) {
        return createEditableField('input', options, {
            className: 'field-input field-enabled',
            type: options.type ?? 'text',
        });
    }

    function createPasswordField(inputOptions) {
        const wrapper = createClassElement('div', 'password-field-wrap');

        const inputOpts = {
            ...inputOptions, type: 'password',
            autocomplete: 'new-password',
        };

        const input = createEditableInput(inputOpts);

        const showKey = typeof LangUtil === 'undefined' ? 'Show' : LangUtil.SHOW_API_KEY;
        const hideKey = typeof LangUtil === 'undefined' ? 'Hide' : LangUtil.HIDE_API_KEY;

        const revealButton = createElement('button', {
            type: 'button',
            className: 'password-reveal-btn',
            ariaLabel: showKey,
            ariaPressed: false,
        }, createClassElement('span', 'eye-icon eye-closed'));

        const onRevealClick = event => {
            event.stopPropagation();

            const isHidden = input.type === 'password';
            input.type = isHidden ? 'text' : 'password';

            revealButton.setAttribute('aria-label', isHidden ? hideKey : showKey);
            revealButton.setAttribute('aria-pressed', String(isHidden));

            const icon = revealButton.querySelector('.eye-icon');

            if (icon) {
                icon.classList.toggle('eye-closed', !isHidden);
                icon.classList.toggle('eye-open', isHidden);
            }
        };

        revealButton.addEventListener('click', onRevealClick);

        wrapper.append(input, revealButton);
        return {wrapper, input};
    }

    return Object.freeze({
        maxAPIKeyLength,
        createElement,
        sanitizeMultiline,
        normalizeProviderName,
        normalizeApiKey,
        createFieldGroup,
        createReadOnlyInput,
        createPasswordField,
    });
})();
