/*
 * Osprey - a browser extension that protects you from malicious websites.
 * Copyright (C) 2025 Foulest (https://github.com/Foulest)
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

// Manages user preferences and configurations.
const Settings = (() => {

    // Key for storing settings in local storage
    const settingsKey = "Settings";

    let defaultSettings = {
        // Official Partners
        adGuardSecurityEnabled: true,
        adGuardFamilyEnabled: false,
        alphaMountainEnabled: true,
        precisionSecEnabled: true,

        // Non-Partnered Providers
        certEEEnabled: false,
        cleanBrowsingSecurityEnabled: true,
        cleanBrowsingFamilyEnabled: false,
        cloudflareSecurityEnabled: true,
        cloudflareFamilyEnabled: false,
        controlDSecurityEnabled: false,
        controlDFamilyEnabled: false,
        dns4EUSecurityEnabled: true,
        dns4EUFamilyEnabled: false,
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
    };

    /**
     * Compares two objects and updates the target object with values from the source object if they differ.
     *
     * @param {Object} target - The target object to update.
     * @param {Object} source - The source object to compare with.
     * @returns {boolean} - Returns true if any values were updated, false otherwise.
     */
    const updateIfChanged = (target, source) => {
        // Checks if the target is valid
        if (!target || typeof target !== 'object') {
            throw new Error('Target must be an object');
        }

        // Checks if the source is valid
        if (!source || typeof source !== 'object') {
            return false;
        }

        let hasChanges = false;

        try {
            // Iterates through the source object properties
            // If the values differ, update the target and mark changes
            for (const key in source) {
                if (Object.hasOwn(source, key) && source[key] !== target[key]) {
                    target[key] = source[key];
                    hasChanges = true;
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
     * @param {Function} callback - The function to call with the retrieved settings.
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
     * Restore the default settings.
     *
     * @param callback - Callback function that will be called after restoring the settings.
     */
    const restoreDefaultSettings = callback => {
        // Saves the default settings back to local storage
        StorageUtil.getFromLocalStore(settingsKey, function () {
            StorageUtil.setToLocalStore(settingsKey, defaultSettings, callback);
        });
    };

    /**
     * Checks if all partner settings are disabled.
     *
     * @param settings - The settings object to check.
     * @returns {boolean} - Returns true if all partner settings are disabled, false otherwise.
     */
    const allPartnersDisabled = settings =>
        !settings.adGuardSecurityEnabled &&
        !settings.adGuardFamilyEnabled &&
        !settings.alphaMountainEnabled &&
        !settings.precisionSecEnabled;

    /**
     * Checks if all security providers are disabled.
     *
     * @param settings - The settings object to check.
     * @returns {boolean} - Returns true if all security providers are disabled, false otherwise.
     */
    const allProvidersDisabled = settings =>
        !settings.adGuardSecurityEnabled &&
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
        !settings.quad9Enabled;

    return {
        get,
        set,
        restoreDefaultSettings,
        allPartnersDisabled,
        allProvidersDisabled,
    };
})();
