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

// Manages user preferences and configurations
const Settings = (() => {

    // Key for storing settings in local storage
    const settingsKey = "Settings";

    // List of keys that are considered dangerous and should not be used for storage
    const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

    const defaultSettings = Object.freeze({
        // Official Partners
        adGuardSecurityEnabled: true,
        adGuardFamilyEnabled: false,
        alphaMountainEnabled: true,
        precisionSecEnabled: false,

        // Non-Partnered Providers
        certEEEnabled: false,
        cleanBrowsingSecurityEnabled: true,
        cleanBrowsingFamilyEnabled: false,
        cloudflareSecurityEnabled: true,
        cloudflareFamilyEnabled: false,
        controlDSecurityEnabled: false,
        controlDFamilyEnabled: false,
        dns4EUSecurityEnabled: false,
        dns4EUFamilyEnabled: false,
        seclookupEnabled: true,
        switchCHEnabled: true,
        quad9Enabled: true,

        // General Settings
        contextMenuEnabled: true,
        notificationsEnabled: false,
        ignoreFrameNavigation: true,
        hideContinueButtons: false,
        hideReportButton: false,
        lockProtectionOptions: false,
        hideProtectionOptions: false,
        cacheExpirationSeconds: 604800, // 7 days in seconds
    });

    /**
     * Compares two objects and updates the target object with values from the source object if they differ.
     *
     * @param {Object} target - The target object to update.
     * @param {Object} source - The source object to compare with.
     * @returns {boolean} - Returns true if any values were updated, false otherwise.
     */
    const updateIfChanged = (target, source) => {
        if (!source || typeof source !== 'object') {
            console.warn(`Invalid source object for settings update, expected an object but got ${typeof source}`);
            return false;
        }

        let hasChanges = false;

        try {
            // Iterates through the source object properties
            // If the values differ, update the target and mark changes
            for (const key in source) {

                // Skips dangerous keys to prevent prototype pollution
                // Only updates keys that exist in defaultSettings
                if (!DANGEROUS_KEYS.has(key) && Object.hasOwn(source, key) && Object.hasOwn(target, key)) {
                    const validatedValue = validateSettingValue(key, source[key], defaultSettings[key]);

                    // Only update the target if the validated value differs from the current value
                    if (validatedValue !== target[key]) {
                        target[key] = validatedValue;
                        hasChanges = true;
                    }
                }
            }
        } catch (error) {
            console.error('Error updating settings:', error);
            throw error;
        }

        // Returns whether any changes were made
        return hasChanges;
    };

    /**
     * Retrieves settings from local storage and merges them with default settings.
     *
     * @param {Function} [callback] - The function to call with the retrieved settings.
     */
    const get = callback => {
        StorageUtil.getFromLocalStore(settingsKey, function (storedSettings) {
            // Clones the default settings object
            let mergedSettings = structuredClone(defaultSettings);

            // Merges any stored settings into the cloned default settings
            updateIfChanged(mergedSettings, storedSettings);

            // Invokes the callback with the merged settings
            callback?.(mergedSettings);
        });
    };

    /**
     * Saves settings to local storage, merging them with any previously stored settings.
     *
     * @param {Object} newSettings - The new settings to save.
     * @param {Function} [callback] - Optional callback to call after settings are saved.
     */
    const set = (newSettings, callback) => {
        if (!newSettings || typeof newSettings !== 'object') {
            console.warn(`Invalid new settings object, expected an object but got ${typeof newSettings}`);
            return;
        }

        StorageUtil.getFromLocalStore(settingsKey, function (storedSettings) {
            // Clones the default settings object
            let mergedSettings = structuredClone(defaultSettings);

            // Merges stored settings and new settings into the cloned default settings
            storedSettings && updateIfChanged(mergedSettings, storedSettings);
            updateIfChanged(mergedSettings, newSettings);

            // Saves the merged settings back to local storage
            StorageUtil.setToLocalStore(settingsKey, mergedSettings, callback);
        });
    };

    /**
     * Restores the default settings.
     *
     * @param {Function} [callback] - Optional callback to call after default settings are restored.
     */
    const restoreDefaultSettings = callback => {
        StorageUtil.getFromLocalStore(settingsKey, function () {
            StorageUtil.setToLocalStore(settingsKey, defaultSettings, callback);
        });
    };

    /**
     * Validates a setting value against its default value to ensure it is of the expected type.
     *
     * @param {string} key - The key of the setting being validated.
     * @param {*} value - The value of the setting to validate.
     * @param {*} defaultValue - The default value of the setting, used to determine the expected type.
     * @returns {*} - Returns the validated value if it is of the expected type, or the default value if it is not.
     */
    const validateSettingValue = (key, value, defaultValue) => {
        if (value === null || value === undefined || defaultValue === null || defaultValue === undefined) {
            console.warn(`Invalid value for setting ${key}, using default value`);
            return defaultValue;
        }

        const expectedType = typeof defaultValue;

        // Checks if the value is of the expected type, if not, logs a warning and returns the default value
        if (typeof value !== expectedType) {
            console.warn(`Invalid type for setting ${key}, using default value`);
            return defaultValue;
        }
        return value;
    };

    /**
     * Checks if all partner settings are disabled.
     *
     * @param {Object} settings - The settings object to check.
     * @returns {boolean} - Returns true if all partner settings are disabled, false otherwise.
     */
    const allPartnersDisabled = settings => {
        return !settings.adGuardSecurityEnabled &&
            !settings.adGuardFamilyEnabled &&
            !settings.alphaMountainEnabled &&
            !settings.precisionSecEnabled;
    };

    /**
     * Checks if all security providers are disabled.
     *
     * @param {Object} settings - The settings object to check.
     * @returns {boolean} - Returns true if all security providers are disabled, false otherwise.
     */
    const allProvidersDisabled = settings => {
        return !settings.adGuardSecurityEnabled &&
            !settings.adGuardFamilyEnabled &&
            !settings.alphaMountainEnabled &&
            !settings.precisionSecEnabled &&
            !settings.certEEEnabled &&
            !settings.cleanBrowsingSecurityEnabled &&
            !settings.cleanBrowsingFamilyEnabled &&
            !settings.cloudflareSecurityEnabled &&
            !settings.cloudflareFamilyEnabled &&
            !settings.controlDSecurityEnabled &&
            !settings.controlDFamilyEnabled &&
            !settings.dns4EUSecurityEnabled &&
            !settings.dns4EUFamilyEnabled &&
            !settings.seclookupEnabled &&
            !settings.switchCHEnabled &&
            !settings.quad9Enabled;
    };

    return Object.freeze({
        get,
        set,
        restoreDefaultSettings,
        allPartnersDisabled,
        allProvidersDisabled,
    });
})();
