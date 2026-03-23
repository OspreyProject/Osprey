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

// Storage utility for interacting with the browser's local storage
globalThis.StorageUtil = (() => {

    // Global variable for browser API compatibility
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    // List of keys that are considered dangerous and should not be used for storage
    const DANGEROUS_KEYS = Object.freeze(['__proto__', 'constructor', 'prototype']);

    // Maximum size for values stored in local storage (5MB)
    const MAX_VALUE_SIZE = 5 * 1024 * 1024;

    // Maximum length for storage keys
    const MAX_KEY_LENGTH = 1024;

    /**
     * Returns true if the given key is considered dangerous.
     *
     * @param {string} key The key to check.
     * @returns {boolean}
     */
    const isDangerousKey = key => DANGEROUS_KEYS.includes(key);

    /**
     * Validates a storage key to ensure it is a non-empty string and does not contain dangerous keys.
     *
     * @param {string} key The key to validate.
     * @returns {boolean} Returns true if the key is valid, false otherwise.
     */
    const isValidKey = (key) => {
        return typeof key === 'string' && key.length > 0 && key.length <= MAX_KEY_LENGTH && !isDangerousKey(key);
    };

    /**
     * Validates a key/value pair and returns the serialized value string.
     * Reports errors through the provided callback rather than throwing,
     * to maintain a consistent async error contract across the public API.
     *
     * @param {string} key The storage key to validate.
     * @param {*} value The value to validate and serialize.
     * @param {Function} fixedCallback The callback to invoke on validation failure.
     * @returns {string|null} The serialized value string, or null if validation failed.
     */
    const validateAndSerialize = (key, value, fixedCallback) => {
        if (typeof value === 'function' || typeof value === 'symbol') {
            console.error('Cannot store functions or symbols');
            fixedCallback(null);
            return null;
        }

        if (!isValidKey(key)) {
            console.error('Key must be a non-empty string and cannot be a dangerous key');
            fixedCallback(null);
            return null;
        }

        let serialized;
        try {
            serialized = JSON.stringify(value);
        } catch (e) {
            console.error(`Value cannot be serialized: ${e.message}`);
            fixedCallback(null);
            return null;
        }

        // Use byte length for an accurate size check (fixes Fix 6 simultaneously)
        const byteLength = new TextEncoder().encode(serialized).byteLength;

        if (byteLength > MAX_VALUE_SIZE) {
            console.error(`Value exceeds maximum allowed size (${byteLength} bytes)`);
            fixedCallback(null);
            return null;
        }

        // Return the serialized string so callers can reuse it rather than re-serializing
        return serialized;
    };

    /**
     * Shared read implementation for local and session storage.
     *
     * @param {object} storageArea The storage area to read from (local or session).
     * @param {string} areaName Human-readable name for error messages.
     * @param {string} key The key to retrieve.
     * @param {Function} fixedCallback The validated callback to invoke with the result.
     */
    const readFromStore = (storageArea, areaName, key, fixedCallback) => {
        if (!isValidKey(key)) {
            console.error('Key must be a non-empty string and cannot be a dangerous key');
            fixedCallback(null);
            return;
        }

        if (!storageArea) {
            console.error(`${areaName} storage API not available`);
            fixedCallback(null);
            return;
        }

        storageArea.get(key, function (result) {
            if (browserAPI.runtime.lastError) {
                console.error('StorageUtil error:', browserAPI.runtime.lastError);
                fixedCallback(new Error(browserAPI.runtime.lastError.message));
                return;
            }

            fixedCallback(null, result?.[key]);
        });
    };

    /**
     * Retrieves data from the browser's local storage.
     *
     * @param {string} key The key to retrieve from local storage.
     * @param {Function} callback The function to call with the retrieved value.
     */
    const getFromLocalStore = (key, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : () => {
        };
        readFromStore(browserAPI.storage?.local, 'Local', key, fixedCallback);
    };

    /**
     * Saves data to the browser's local storage.
     *
     * @param {string} key The key to save to local storage.
     * @param {any} value The value to store.
     * @param {Function} [callback] Optional callback to call after saving.
     */
    const setToLocalStore = (key, value, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : (err) => {
            if (err) {
                console.error(`StorageUtil: unhandled write error (no callback provided): ${err.message}`);
            }
        };

        if (validateAndSerialize(key, value, fixedCallback) === null) {
            return;
        }

        const data = {[key]: value};

        browserAPI.storage.local.set(data, function () {
            if (browserAPI.runtime.lastError) {
                console.error('StorageUtil error:', browserAPI.runtime.lastError);
                fixedCallback(new Error(browserAPI.runtime.lastError.message));
                return;
            }

            fixedCallback();
        });
    };

    /**
     * Retrieves data from the browser's session storage.
     *
     * @param {string} key The key to retrieve from session storage.
     * @param {Function} callback The function to call with the retrieved value.
     */
    const getFromSessionStore = (key, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : () => {
        };
        readFromStore(browserAPI.storage?.session, 'Session', key, fixedCallback);
    };

    /**
     * Saves data to the browser's session storage.
     *
     * @param {string} key The key to save to session storage.
     * @param {any} value The value to store.
     * @param {Function} [callback] Optional callback to call after saving.
     */
    const setToSessionStore = (key, value, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : (err) => {
            if (err) {
                console.error(`StorageUtil: unhandled write error (no callback provided): ${err.message}`);
            }
        };

        if (validateAndSerialize(key, value, fixedCallback) === null) {
            return;
        }

        if (!browserAPI.storage?.session) {
            console.error('Session storage API not available');
            fixedCallback(null);
            return;
        }

        const data = {[key]: value};

        browserAPI.storage.session.set(data, function () {
            if (browserAPI.runtime?.lastError) {
                console.error('StorageUtil error:', browserAPI.runtime.lastError);
                fixedCallback(new Error(browserAPI.runtime.lastError.message));
                return;
            }

            fixedCallback(null);
        });
    };

    return Object.freeze({
        getFromLocalStore,
        setToLocalStore,
        getFromSessionStore,
        setToSessionStore,
        isDangerousKey,
    });
})();
