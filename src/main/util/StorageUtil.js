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
const StorageUtil = (() => {

    // Global variable for browser API compatibility
    const browserAPI = globalThis.chrome ?? globalThis.browser;

    // List of keys that are considered dangerous and should not be used for storage
    const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

    // Maximum size for values stored in local storage (5MB)
    const MAX_VALUE_SIZE = 5 * 1024 * 1024;

    /**
     * Retrieves data from the browser's local storage.
     *
     * @param {string} key - The key to retrieve from local storage.
     * @param {Function} callback - The function to call with the retrieved value.
     */
    const getFromLocalStore = (key, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : () => {
        };

        // Checks if the key is valid
        if (!isValidKey(key)) {
            throw new TypeError('Key must be a non-empty string and cannot be a dangerous key');
        }

        // Checks if local storage is supported
        if (!browserAPI?.storage?.local) {
            console.error('Local storage API not available');
            fixedCallback(null);
            return;
        }

        browserAPI.storage.local.get(key, function (result) {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('StorageUtil error:', browserAPI.runtime.lastError);
                fixedCallback(null);
                return;
            }

            // Extracts the value associated with the key
            let value = result?.[key];

            // Calls the callback function with the retrieved value
            fixedCallback(value);
        });
    };

    /**
     * Saves data to the browser's local storage.
     *
     * @param {string} key - The key to save to local storage.
     * @param {any} value - The value to store.
     * @param {Function} [callback] - Optional callback to call after saving.
     */
    const setToLocalStore = (key, value, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : () => {
        };

        // Prevents storing functions or symbols
        if (typeof value === 'function' || typeof value === 'symbol') {
            throw new TypeError('Cannot store functions or symbols');
        }

        // Checks if the key is valid
        if (!isValidKey(key)) {
            throw new TypeError('Key must be a non-empty string and cannot be a dangerous key');
        }

        const serialized = JSON.stringify(value);

        // Checks if the serialized value exceeds the maximum allowed size
        if (serialized.length > MAX_VALUE_SIZE) {
            throw new Error('Value exceeds maximum allowed size');
        }

        // Checks if local storage is supported
        if (!browserAPI?.storage?.local) {
            console.error('Local storage API not available');
            fixedCallback(null);
            return;
        }

        // Creates an object to hold the key-value pair
        let data = {};
        data[key] = value;

        browserAPI.storage.local.set(data, function () {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('StorageUtil error:', browserAPI.runtime.lastError);
                fixedCallback(null);
                return;
            }

            // Completes the callback
            fixedCallback();
        });
    };

    /**
     * Retrieves data from the browser's session storage.
     *
     * @param {string} key - The key to retrieve from session storage.
     * @param {Function} callback - The function to call with the retrieved value.
     */
    const getFromSessionStore = (key, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : () => {
        };

        // Checks if the key is valid
        if (!isValidKey(key)) {
            throw new TypeError('Key must be a non-empty string and cannot be a dangerous key');
        }

        // Checks if session storage is supported
        if (!browserAPI?.storage?.session) {
            console.error('Session storage API not available');
            callback(null);
            return;
        }

        browserAPI.storage.session.get(key, function (result) {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('StorageUtil error:', browserAPI.runtime.lastError);
                fixedCallback(null);
                return;
            }

            // Extracts the value associated with the key.
            let value = result?.[key];

            // Calls the callback function with the retrieved value.
            fixedCallback(value);
        });
    };

    /**
     * Saves data to the browser's session storage.
     *
     * @param {string} key - The key to save to session storage.
     * @param {any} value - The value to store.
     * @param {Function} [callback] - Optional callback to call after saving.
     */
    const setToSessionStore = (key, value, callback) => {
        const fixedCallback = typeof callback === 'function' ? callback : () => {
        };

        // Prevents storing functions or symbols
        if (typeof value === 'function' || typeof value === 'symbol') {
            throw new TypeError('Cannot store functions or symbols');
        }

        // Checks if the key is valid
        if (!isValidKey(key)) {
            throw new TypeError('Key must be a non-empty string and cannot be a dangerous key');
        }

        const serialized = JSON.stringify(value);

        // Checks if the serialized value exceeds the maximum allowed size
        if (serialized.length > MAX_VALUE_SIZE) {
            throw new Error('Value exceeds maximum allowed size');
        }

        // Checks if session storage is supported
        if (!browserAPI?.storage?.session) {
            console.error('Session storage API not available');
            fixedCallback(null);
            return;
        }

        // Creates an object to hold the key-value pair
        let data = {};
        data[key] = value;

        browserAPI.storage.session.set(data, function () {
            // Handles errors in the storage process
            if (browserAPI.runtime.lastError) {
                console.error('StorageUtil error:', browserAPI.runtime.lastError);
                fixedCallback(null);
                return;
            }

            // Completes the callback
            fixedCallback();
        });
    };

    /**
     * Validates a storage key to ensure it is a non-empty string and does not contain dangerous keys.
     *
     * @param {string} key - The key to validate.
     * @returns {boolean} - Returns true if the key is valid, false otherwise.
     */
    const isValidKey = (key) => {
        return typeof key === 'string' && key.length > 0 && !DANGEROUS_KEYS.has(key);
    };

    return {
        getFromLocalStore,
        setToLocalStore,
        getFromSessionStore,
        setToSessionStore
    };
})();
