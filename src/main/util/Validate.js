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
     * Validates that the response Content-Type matches the expected type.
     *
     * @param {Response} response The fetch response to validate.
     * @param {string} expected The expected Content-Type (e.g., 'application/json').
     * @returns {boolean} True if Content-Type matches, false otherwise.
     */
    const hasValidContentType = (response, expected) => {
        if (response?.headers === null || typeof expected !== 'string') {
            return false;
        }

        const contentType = response.headers.get('Content-Type') || '';
        const mediaType = contentType.split(';')[0].trim().toLowerCase();
        return mediaType === expected.toLowerCase();
    };

    /**
     * Checks if a URL has a valid HTTP or HTTPS protocol.
     *
     * @param {URL} urlObject The URL object to check.
     * @param {Set<string>} validProtocols Set of valid protocol strings (e.g., 'http:', 'https:').
     * @returns {boolean} True if protocol is valid, false otherwise.
     */
    const hasValidProtocol = (urlObject, validProtocols) => {
        if (urlObject === null || typeof urlObject.protocol !== 'string') {
            return false;
        }
        return validProtocols.has(urlObject.protocol.toLowerCase());
    };

    /**
     * Validates that a URL string parses correctly and has a valid HTTP(S) protocol.
     *
     * @param {string} urlString The URL string to validate.
     * @param {Set<string>} validProtocols Set of valid protocol strings.
     * @returns {{valid: boolean, url: URL|null, error: string|null}} Validation result object.
     */
    const validateHttpUrl = (urlString, validProtocols) => {
        if (!(validProtocols instanceof Set) || validProtocols.size === 0) {
            return {valid: false, url: null, error: 'validProtocols must be a non-empty Set'};
        }

        if (urlString === null) {
            return {valid: false, url: null, error: 'URL string is null or undefined'};
        }

        if (typeof urlString !== 'string' || urlString.trim().length === 0) {
            return {valid: false, url: null, error: 'URL string is blank'};
        }

        let url;
        try {
            url = new URL(urlString);
        } catch (error) {
            return {valid: false, url: null, error: error.message};
        }

        if (!hasValidProtocol(url, validProtocols)) {
            return {valid: false, url, error: `Invalid protocol: ${url.protocol}`};
        }
        return {valid: true, url, error: null};
    };

    // Public API
    return Object.freeze({
        hasValidContentType,
        hasValidProtocol,
        validateHttpUrl,
    });
})();
