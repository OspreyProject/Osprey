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
globalThis.Settings = (() => {

    // Key for storing settings in local storage
    const settingsKey = "Settings";

    // In-memory cache for fast synchronous reads
    let cachedSettings = null;

    const defaultSettings = Object.freeze({
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
        quad9Enabled: true,
        switchCHEnabled: true,

        // Local Filtering Lists
        phishDestroyEnabled: true,
        phishingDatabaseEnabled: true,

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

    // Derived once from defaultSettings: the set of boolean keys that enable a protection provider.
    // Any key ending in "Enabled" that is boolean and is not a UI/policy toggle is a provider key.
    const _providerEnabledKeys = Object.freeze(
        Object.keys(defaultSettings).filter(key =>
            key.endsWith('Enabled') &&
            typeof defaultSettings[key] === 'boolean' &&
            !['contextMenuEnabled', 'notificationsEnabled'].includes(key)
        )
    );

    console.assert(
        _providerEnabledKeys.length === 15,
        `Settings: expected 15 provider keys but found ${_providerEnabledKeys.length}; update the exclusion
            list in allProvidersDisabled if a new provider or UI setting was added`
    );

    /**
     * Compares two objects and updates the target object with values from the source object if they differ.
     *
     * @param {Object} target The target object to update.
     * @param {Object} source The source object to compare with.
     * @returns {boolean} Returns true if any values were updated, false otherwise.
     */
    const updateIfChanged = (target, source) => {
        // This happens when there are no stored settings yet, so we can skip the update process
        // Not logging an error here prevents unnecessarily spamming the console with errors
        if (!source) {
            return false;
        }

        // Validates that the source is an object before proceeding with the update
        if (typeof source !== 'object') {
            console.warn(`Invalid source object for settings update, expected an object but got ${typeof source}`);
            return false;
        }

        let hasChanges = false;

        try {
            // Iterates through known default keys rather than source keys,
            // making it immediately auditable that only known keys are ever processed.
            for (const key of Object.keys(defaultSettings)) {

                // Skips dangerous keys to prevent prototype pollution
                if (StorageUtil.isDangerousKey(key)) {
                    continue;
                }

                // Only update if the source actually has this key
                if (!Object.hasOwn(source, key)) {
                    continue;
                }

                const validatedValue = validateSettingValue(key, source[key], defaultSettings[key]);

                // Only update the target if the validated value differs from the current value
                if (validatedValue !== target[key]) {
                    target[key] = validatedValue;
                    hasChanges = true;
                }
            }
        } catch (error) {
            console.error('Error updating settings:', error);
            return false;
        }

        // Returns whether any changes were made
        return hasChanges;
    };

    /**
     * Retrieves settings, serving from the in-memory cache when available
     * to avoid a storage round-trip on every call.
     *
     * @param {Function} [callback] The function to call with the retrieved settings.
     */
    const get = callback => {
        // If the cache is warm, serve a shallow copy to prevent callers from mutating the cache.
        // Settings values are all primitives (booleans and numbers), so a shallow copy is sufficient.
        if (cachedSettings !== null) {
            callback?.(Object.assign(Object.create(null), cachedSettings));
            return;
        }

        // Cache is cold (first call after service worker start); load from storage
        StorageUtil.getFromLocalStore(settingsKey, function (_, storedSettings) {
            // Clones the default settings object
            let mergedSettings = structuredClone(defaultSettings);

            // Merges any stored settings into the cloned default settings
            updateIfChanged(mergedSettings, storedSettings);

            // Warms the cached settings
            cachedSettings = mergedSettings;

            // Invokes the callback with a clone to prevent callers from mutating the cache
            callback?.(structuredClone(mergedSettings));
        });
    };

    /**
     * Saves settings to local storage, merging them with any previously stored settings.
     *
     * @param {Object} newSettings The new settings to save.
     * @param {Function} [callback] Optional callback to call after settings are saved.
     */
    const set = (newSettings, callback) => {
        if (!newSettings || typeof newSettings !== 'object' || Array.isArray(newSettings)) {
            console.warn(`Invalid new settings object, expected an object but got ${typeof newSettings}`);
            return;
        }

        // Use the cache as the base if warm, otherwise fall back to defaults
        const base = cachedSettings === null ? structuredClone(defaultSettings) : structuredClone(cachedSettings);
        updateIfChanged(base, newSettings);

        // Capture the previous cache state for rollback on storage failure
        const previousCache = cachedSettings;

        // Keep the cache in sync immediately, don't wait for the storage write
        cachedSettings = base;

        // Persist to storage; roll back the cache if the write fails
        StorageUtil.setToLocalStore(settingsKey, base, (err) => {
            if (err) {
                console.error(`Settings.set: storage write failed: ${err.message}. Rolling back cache.`);
                cachedSettings = previousCache;
                return;
            }

            callback?.(null);
        });
    };

    /**
     * Restores the default settings.
     *
     * @param {Function} [callback] Optional callback to call after default settings are restored.
     */
    const restoreDefaultSettings = callback => {
        // Resets the cache
        const restored = structuredClone(defaultSettings);
        cachedSettings = restored;

        // Saves the default settings to local storage, overwriting any existing settings
        StorageUtil.setToLocalStore(settingsKey, restored, callback);
    };

    /**
     * Validates a setting value against its default value to ensure it is of the expected type.
     *
     * @param {string} key The key of the setting being validated.
     * @param {*} value The value of the setting to validate.
     * @param {*} defaultValue The default value of the setting, used to determine the expected type.
     * @returns {*} Returns the validated value if it is of the expected type, or the default value if it is not.
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

        // Range-checks numeric time values to prevent degenerate cache behavior
        if (key === 'cacheExpirationSeconds' && (value <= 0 || !Number.isFinite(value))) {
            console.warn(`Invalid value for cacheExpirationSeconds, using default value`);
            return defaultValue;
        }
        return value;
    };

    /**
     * Invalidates the in-memory cache, forcing the next get() call to re-read from storage.
     */
    const invalidateCache = () => {
        cachedSettings = null;
    };

    /**
     * Checks if all security providers are disabled.
     *
     * @param {Object} settings The settings object to check.
     * @returns {boolean} Returns true if all security providers are disabled, false otherwise.
     */
    const allProvidersDisabled = settings => {
        if (!settings || typeof settings !== 'object' || Array.isArray(settings)) {
            console.warn('allProvidersDisabled: invalid settings object provided');
            return false;
        }
        return _providerEnabledKeys.every(key => !settings[key]);
    };

    return Object.freeze({
        get,
        set,
        restoreDefaultSettings,
        allProvidersDisabled,
        invalidateCache,
    });
})();
