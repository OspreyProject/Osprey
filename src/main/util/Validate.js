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

/**
 * Utility class for validation.
 * Provides static methods for common validation patterns used throughout the extension.
 */
const Validate = (() => {

    /**
     * Checks if a value is null or undefined.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if null or undefined, false otherwise.
     */
    const isNullish = value => {
        return value === null || value === undefined || !value && typeof value !== 'boolean' && typeof value !== 'number';
    };

    /**
     * Checks if a value is not null and not undefined.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if not null/undefined, false otherwise.
     */
    const isNotNull = value => {
        return !isNullish(value);
    };

    /**
     * Checks if the value is a non-blank string.
     *
     * @param {*} value - The value to check.
     * @returns {boolean} - True if non-blank string, false otherwise.
     */
    const isNotBlank = value => {
        return isNotNull(value) && typeof value === 'string' && value.trim().length > 0;
    };

    /**
     * Validates that the response Content-Type matches the expected type.
     *
     * @param {Response} response - The fetch response to validate.
     * @param {string} expected - The expected Content-Type (e.g., 'application/json').
     * @returns {boolean} - True if Content-Type matches, false otherwise.
     */
    const hasValidContentType = (response, expected) => {
        const contentType = response.headers.get('Content-Type') || '';
        return contentType.toLowerCase().includes(expected.toLowerCase());
    };

    /**
     * Checks if a URL string is valid and can be parsed into a URL object.
     *
     * @param {string} urlString - The URL string to parse.
     * @returns {{valid: boolean, url: URL|null, error: string|null}} - Parse result object.
     */
    const parseUrl = urlString => {
        if (!isNotNull(urlString)) {
            return {valid: false, url: null, error: 'URL string is null or undefined'};
        }

        if (!isNotBlank(urlString)) {
            return {valid: false, url: null, error: 'URL string is blank'};
        }

        try {
            const url = new URL(urlString);
            return {valid: true, url: url, error: null};
        } catch (error) {
            return {valid: false, url: null, error: error.message};
        }
    };

    /**
     * Checks if a URL has a valid HTTP or HTTPS protocol.
     *
     * @param {URL} urlObject - The URL object to check.
     * @param {Set<string>} validProtocols - Set of valid protocol strings (e.g., 'http:', 'https:').
     * @returns {boolean} - True if protocol is valid, false otherwise.
     */
    const hasValidProtocol = (urlObject, validProtocols) => {
        if (!isNotNull(urlObject) || typeof urlObject.protocol !== 'string') {
            return false;
        }
        return validProtocols.has(urlObject.protocol.toLowerCase());
    };

    /**
     * Validates that a URL string parses correctly and has a valid HTTP(S) protocol.
     *
     * @param {string} urlString - The URL string to validate.
     * @param {Set<string>} validProtocols - Set of valid protocol strings.
     * @returns {{valid: boolean, url: URL|null, error: string|null}} - Validation result object.
     */
    const validateHttpUrl = (urlString, validProtocols) => {
        const parseResult = parseUrl(urlString);

        if (!parseResult.valid) {
            return parseResult;
        }

        if (!hasValidProtocol(parseResult.url, validProtocols)) {
            return {
                valid: false,
                url: parseResult.url,
                error: `Invalid protocol: ${parseResult.url.protocol}`
            };
        }
        return parseResult;
    };

    // Public API
    return Object.freeze({
        hasValidContentType,
        hasValidProtocol,
        validateHttpUrl,
    });
})();
